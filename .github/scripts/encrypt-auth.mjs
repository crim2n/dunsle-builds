// 수정용 열쇠(EDIT_TOKEN)를 비밀번호(EDIT_PASSWORD)로 암호화해 data/auth.json 에 저장.
// 두 값 모두 저장소 Secrets 에만 있고, 결과 파일에는 암호문만 들어간다.
import { webcrypto as crypto } from 'node:crypto';
import fs from 'node:fs';

const token = process.env.EDIT_TOKEN;
const password = process.env.EDIT_PASSWORD;
if (!token || !password) {
    console.error('Secrets 에 EDIT_TOKEN 과 EDIT_PASSWORD 가 모두 있어야 합니다.');
    process.exit(1);
}

const ITER = 600000;   // 비밀번호 대입 공격을 느리게 만드는 반복 횟수 (사이트와 동일해야 함)
const salt = crypto.getRandomValues(new Uint8Array(16));
const iv = crypto.getRandomValues(new Uint8Array(12));
const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: ITER, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(token)));

const b64 = u => Buffer.from(u).toString('base64');
fs.writeFileSync('data/auth.json', JSON.stringify({
    v: 1, kdf: 'PBKDF2-SHA256', iter: ITER,
    salt: b64(salt), iv: b64(iv), ct: b64(ct),
    updated: new Date().toISOString(),
}, null, 2) + '\n');
console.log('data/auth.json 갱신 완료');
