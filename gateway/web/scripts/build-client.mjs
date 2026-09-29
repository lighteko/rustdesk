import {mkdir, readFile, writeFile, cp} from 'node:fs/promises';
import {createRequire} from 'node:module';
import {build} from 'vite';

const require = createRequire(import.meta.url);
const pbjs = require('protobufjs-cli/pbjs');
const pbts = require('protobufjs-cli/pbts');
await mkdir('src/remote/generated', {recursive:true});
const generate = (tool, args) => new Promise((resolve, reject) => tool.main(args, (error, output) => error ? reject(error) : resolve(output)));
await writeFile('src/remote/generated/desktop.js', await generate(pbjs, ['-t','static-module','-w','es6','--force-number','--no-service','--no-delimited','--no-verify','protocol/desktop.proto']));
await writeFile('src/remote/generated/desktop.d.ts', await generate(pbts, ['src/remote/generated/desktop.js']));
await build({configFile:false, build:{outDir:'../client', emptyOutDir:true, lib:{entry:'src/remote/client.ts', formats:['es'], fileName:()=>'adapter.js'}, rollupOptions:{output:{inlineDynamicImports:true}}}});
await cp('node_modules/ogv/dist', '../client/ogv', {recursive:true});
const versions = JSON.parse(await readFile('package.json', 'utf8')).dependencies;
await writeFile('../client/provenance.json', JSON.stringify({protocol:'a7f2260203befb7e9c70b585219f0f0b5ca57703', dependencies:versions}, null, 2));
