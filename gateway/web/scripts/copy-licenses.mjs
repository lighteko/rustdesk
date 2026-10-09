import {copyFile, mkdir} from 'node:fs/promises';

for (const target of ['../client/licenses', 'dist/licenses']) await mkdir(target, {recursive:true});
for (const [name, file] of [
  ['libsodium-wrappers', 'LICENSE'], ['libsodium', 'LICENSE'],
  ['protobufjs', 'LICENSE'], ['ogv', 'COPYING'],
]) await copyFile(`node_modules/${name}/${file}`, `../client/licenses/${name}.txt`);
for (const name of ['react', 'react-dom']) {
  await copyFile(`node_modules/${name}/LICENSE`, `dist/licenses/${name}.txt`);
}
