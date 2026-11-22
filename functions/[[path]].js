import { connect } from 'cloudflare:sockets';

const USER_ID = '11111111-2222-3333-4444-555555555555';
const SOCKS5_CONFIG = {
  user: '21398f2b830c7f666807745abedf8598',
  pass: 'v1.498700.58db82a3.bd65ba72e1fe74e7fab97e23',
  host: '135.125.189.205',
  port: 8443,
};

export async function onRequest(context) {
  const request = context.request;
  if (request.headers.get('Upgrade') !== 'websocket') {
    return new Response('OK', { status: 200 });
  }

  const [client, server] = Object.values(new WebSocketPair());
  server.accept();

  const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
  const readableStream = makeReadableWebSocketStream(server, earlyDataHeader);

  let remoteSocket = null;
  let isHeaderParsed = false;

  readableStream.pipeTo(
    new WritableStream({
      async write(chunk) {
        if (isHeaderParsed && remoteSocket) {
          const writer = remoteSocket.writable.getWriter();
          await writer.write(chunk);
          writer.releaseLock();
          return;
        }

        const parsed = parseVlessHeader(chunk, USER_ID);
        if (parsed.hasError || parsed.command !== 1) {
          throw new Error(parsed.message || 'Unsupported command');
        }

        isHeaderParsed = true;
        const responseHeader = new Uint8Array([parsed.version, 0]);
        const initialPayload = chunk.slice(parsed.rawDataIndex);

        remoteSocket = await socks5Connect(
          parsed.addressType,
          parsed.address,
          parsed.port
        );

        const writer = remoteSocket.writable.getWriter();
        if (initialPayload.byteLength > 0) {
          await writer.write(initialPayload);
        }
        writer.releaseLock();

        pipeRemoteToWebSocket(remoteSocket, server, responseHeader);
      },
      close() {
        if (remoteSocket) remoteSocket.close();
      },
      abort() {
        if (remoteSocket) remoteSocket.close();
      },
    })
  ).catch(() => {
    try { server.close(); } catch {}
  });

  return new Response(null, { status: 101, webSocket: client });
}

function makeReadableWebSocketStream(ws, earlyDataHeader) {
  return new ReadableStream({
    start(controller) {
      ws.addEventListener('message', (event) => controller.enqueue(event.data));
      ws.addEventListener('close', () => controller.close());
      ws.addEventListener('error', (err) => controller.error(err));

      if (earlyDataHeader) {
        try {
          const base64 = earlyDataHeader.replace(/-/g, '+').replace(/_/g, '/');
          const binary = atob(base64);
          const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
          controller.enqueue(bytes.buffer);
        } catch {}
      }
    },
  });
}

function parseVlessHeader(buffer, userId) {
  if (buffer.byteLength < 24) {
    return { hasError: true, message: 'Invalid VLESS header length' };
  }
  const view = new DataView(buffer);
  const version = view.getUint8(0);

  const uuidHex = [...new Uint8Array(buffer.slice(1, 17))]
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  const formattedUuid = `${uuidHex.slice(0, 8)}-${uuidHex.slice(8, 12)}-${uuidHex.slice(12, 16)}-${uuidHex.slice(16, 20)}-${uuidHex.slice(20)}`;
  if (formattedUuid !== userId.toLowerCase()) {
    return { hasError: true, message: 'Invalid UUID' };
  }

  const optLen = view.getUint8(17);
  const command = view.getUint8(18 + optLen);
  const portIndex = 19 + optLen;
  const port = view.getUint16(portIndex);
  let addressIndex = portIndex + 2;
  const addressType = view.getUint8(addressIndex++);

  let address = '';
  if (addressType === 1) {
    address = new Uint8Array(buffer.slice(addressIndex, addressIndex + 4)).join('.');
    addressIndex += 4;
  } else if (addressType === 2) {
    const domainLen = view.getUint8(addressIndex++);
    address = new TextDecoder().decode(buffer.slice(addressIndex, addressIndex + domainLen));
    addressIndex += domainLen;
  } else if (addressType === 3) {
    const ipv6 = [];
    for (let i = 0; i < 8; i++) {
      ipv6.push(view.getUint16(addressIndex + i * 2).toString(16));
    }
    address = ipv6.join(':');
    addressIndex += 16;
  } else {
    return { hasError: true, message: 'Unsupported address type' };
  }

  return {
    hasError: false,
    version,
    command,
    port,
    addressType,
    address,
    rawDataIndex: addressIndex,
  };
}

async function socks5Connect(addressType, address, port) {
  const socket = connect({ hostname: SOCKS5_CONFIG.host, port: SOCKS5_CONFIG.port });
  const writer = socket.writable.getWriter();
  const reader = socket.readable.getReader();

  try {
    await writer.write(new Uint8Array([5, 1, 2]));
    let res = (await reader.read()).value;
    if (!res || res[0] !== 5 || res[1] !== 2) {
      throw new Error('SOCKS5 auth method rejected');
    }

    const enc = new TextEncoder();
    const userBytes = enc.encode(SOCKS5_CONFIG.user);
    const passBytes = enc.encode(SOCKS5_CONFIG.pass);
    const authPacket = new Uint8Array(3 + userBytes.length + passBytes.length);
    authPacket[0] = 1;
    authPacket[1] = userBytes.length;
    authPacket.set(userBytes, 2);
    authPacket[2 + userBytes.length] = passBytes.length;
    authPacket.set(passBytes, 3 + userBytes.length);
    await writer.write(authPacket);

    res = (await reader.read()).value;
    if (!res || res[1] !== 0) {
      throw new Error('SOCKS5 authentication failed');
    }

    let addrBytes;
    if (addressType === 1) {
      addrBytes = new Uint8Array([1, ...address.split('.').map(Number)]);
    } else if (addressType === 2) {
      const dom = enc.encode(address);
      addrBytes = new Uint8Array([3, dom.length, ...dom]);
    } else {
      const parts = address.split(':').map((p) => parseInt(p || '0', 16));
      addrBytes = new Uint8Array(17);
      addrBytes[0] = 4;
      const v = new DataView(addrBytes.buffer);
      parts.forEach((val, idx) => v.setUint16(1 + idx * 2, val));
    }

    const reqPacket = new Uint8Array(3 + addrBytes.length + 2);
    reqPacket.set([5, 1, 0], 0);
    reqPacket.set(addrBytes, 3);
    new DataView(reqPacket.buffer).setUint16(3 + addrBytes.length, port);
    await writer.write(reqPacket);

    res = (await reader.read()).value;
    if (!res || res[1] !== 0) {
      throw new Error('SOCKS5 target connection failed');
    }
  } finally {
    writer.releaseLock();
    reader.releaseLock();
  }

  return socket;
}

async function pipeRemoteToWebSocket(remoteSocket, ws, vlessHeader) {
  let sentHeader = false;
  await remoteSocket.readable.pipeTo(
    new WritableStream({
      write(chunk) {
        if (!sentHeader) {
          const combined = new Uint8Array(vlessHeader.byteLength + chunk.byteLength);
          combined.set(vlessHeader, 0);
          combined.set(new Uint8Array(chunk), vlessHeader.byteLength);
          ws.send(combined.buffer);
          sentHeader = true;
        } else {
          ws.send(chunk);
        }
      },
      close() {
        try { ws.close(); } catch {}
      },
      abort() {
        try { ws.close(); } catch {}
      },
    })
  ).catch(() => {
    try { ws.close(); } catch {}
  });
}
