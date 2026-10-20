// Generates the reference mDNS response packet used as the verification
// dataset. Kept independent of the Go decoder on purpose so the Go test
// cross-checks its parser against a second implementation.
const fs = require('fs');
const path = require('path');

const T_A = 1;
const T_PTR = 12;
const T_TXT = 16;
const T_AAAA = 28;
const T_SRV = 33;

function encodeName(value) {
  const parts = [];
  for (const label of value.replace(/\.$/, '').split('.')) {
    parts.push(Buffer.from([label.length]), Buffer.from(label, 'ascii'));
  }
  parts.push(Buffer.from([0]));
  return Buffer.concat(parts);
}

function rr(owner, type, ttl, rdata) {
  const head = Buffer.alloc(10);
  head.writeUInt16BE(type, 0);
  head.writeUInt16BE(1, 2);
  head.writeUInt32BE(ttl, 4);
  head.writeUInt16BE(rdata.length, 8);
  return Buffer.concat([encodeName(owner), head, rdata]);
}

function txt(pairs) {
  const chunks = [];
  for (const [key, value] of pairs) {
    const item = Buffer.from(`${key}=${value}`, 'ascii');
    chunks.push(Buffer.from([item.length]), item);
  }
  return Buffer.concat(chunks);
}

function srv(port, target) {
  const head = Buffer.alloc(6);
  head.writeUInt16BE(0, 0);
  head.writeUInt16BE(0, 2);
  head.writeUInt16BE(port, 4);
  return Buffer.concat([head, encodeName(target)]);
}

const records = [];

for (const service of [
  '_workstation._tcp.local',
  '_http._tcp.local',
  '_smb._tcp.local',
  '_qdiscover._tcp.local',
  '_device-info._tcp.local',
  '_afpovertcp._tcp.local',
]) {
  records.push(rr('_services._dns-sd._udp.local', T_PTR, 4500, encodeName(service)));
}

records.push(rr('slw-nas.local', T_A, 10, Buffer.from([192, 168, 1, 10])));
records.push(rr('slw-nas.local', T_AAAA, 10, Buffer.from('fe80000000000000265ebefffe69a313', 'hex')));

records.push(rr('slw-nas._workstation._tcp.local', T_SRV, 10, srv(9, 'slw-nas.local')));
records.push(rr('slw-nas._workstation._tcp.local', T_TXT, 10, txt([['mac', '24:5e:be:69:a3:13']])));

records.push(rr('slw-nas._http._tcp.local', T_SRV, 10, srv(5000, 'slw-nas.local')));
records.push(rr('slw-nas._http._tcp.local', T_TXT, 10, txt([['path', '/']])));

records.push(rr('slw-nas._smb._tcp.local', T_SRV, 10, srv(445, 'slw-nas.local')));

records.push(rr('slw-nas._qdiscover._tcp.local', T_SRV, 10, srv(5000, 'slw-nas.local')));
records.push(
  rr(
    'slw-nas._qdiscover._tcp.local',
    T_TXT,
    10,
    txt([
      ['accessType', 'https'],
      ['accessPort', '86'],
      ['model', 'TS-X64'],
      ['displayModel', 'TS-464C'],
      ['fwVer', '5.2.9'],
      ['fwBuildNum', '20260214'],
    ])
  )
);

records.push(rr('_device-info._tcp.local', T_PTR, 4500, encodeName('slw-nas(AFP)._device-info._tcp.local')));
records.push(rr('slw-nas(AFP)._device-info._tcp.local', T_TXT, 10, txt([['model', 'Xserve']])));

records.push(rr('slw-nas(AFP)._afpovertcp._tcp.local', T_SRV, 10, srv(548, 'slw-nas.local')));

// Service-instance PTRs must never surface as answers.
records.push(rr('_http._tcp.local', T_PTR, 4500, encodeName('slw-nas._http._tcp.local')));
records.push(rr('_smb._tcp.local', T_PTR, 4500, encodeName('slw-nas._smb._tcp.local')));

const header = Buffer.alloc(12);
header.writeUInt16BE(0, 0);
header.writeUInt16BE(0x8400, 2);
header.writeUInt16BE(0, 4);
header.writeUInt16BE(records.length, 6);

const packet = Buffer.concat([header, ...records]);
fs.writeFileSync(path.join(__dirname, 'reference-mdns.hex'), `${packet.toString('hex')}\n`);
console.log(`records=${records.length} bytes=${packet.length}`);
