#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import {TextDecoder} from 'node:util';
import {evaluateHealth,incomplete,LIMITS} from '../src/index.mjs';
function options(argv){const result={};if(argv.length!==6)return null;for(let i=0;i<argv.length;i+=2){const k=argv[i];if(!['--root','--policy','--capture'].includes(k)||Object.hasOwn(result,k)||!argv[i+1])return null;result[k]=argv[i+1];}return Object.keys(result).length===3?result:null;}
function duplicateKeys(text){const stack=[];for(const match of text.matchAll(/"(?:\\.|[^"\\])*"|[{}\[\],:]/gs)){const token=match[0],top=stack.at(-1);if(token==='{'){stack.push({kind:'object',key:true,seen:new Set()});continue;}if(token==='['){stack.push({kind:'array'});continue;}if(token==='}'||token===']'){stack.pop();continue;}if(token===','){if(top?.kind==='object')top.key=true;continue;}if(token===':')continue;if(top?.kind==='object'&&top.key){const key=JSON.parse(token);if(top.seen.has(key))return true;top.seen.add(key);top.key=false;}}return false;}
function read(root,relative,limit){if(path.isAbsolute(relative))return {error:'input-unreadable'};let target;try{target=fs.realpathSync(path.resolve(root,relative));if(target===root||!target.startsWith(root+path.sep)||!fs.statSync(target).isFile())return {error:'input-unreadable'};}catch{return {error:'input-unreadable'};}let raw;try{raw=fs.readFileSync(target);}catch{return {error:'input-unreadable'};}if(raw.length>limit)return {error:'byte-limit'};try{const text=new TextDecoder('utf-8',{fatal:true}).decode(raw),value=JSON.parse(text);if(duplicateKeys(text))return {error:'input-invalid'};return {value};}catch{return {error:'input-invalid'};}}
export function main(argv,now=()=>performance.now()){
  const args=options(argv);if(!args){process.stderr.write('Usage: deployment-health-gate --root DIR --policy FILE --capture FILE\n');return 2;}
  let root;try{root=fs.realpathSync(args['--root']);if(!fs.statSync(root).isDirectory())throw Error();}catch{process.stderr.write('Invalid root.\n');return 2;}
  const policy=read(root,args['--policy'],LIMITS.policyBytes);if(policy.error){process.stderr.write('Invalid policy.\n');return 2;}
  const capture=read(root,args['--capture'],LIMITS.captureBytes);if(capture.error){process.stdout.write(JSON.stringify(incomplete(capture.error,'@capture'))+'\n');return 2;}
  const result=evaluateHealth(policy.value,capture.value,{now});if(result.status==='incomplete'&&result.findings.some(x=>x.location.file==='@policy')){process.stderr.write('Invalid policy.\n');return 2;}
  process.stdout.write(JSON.stringify(result)+'\n');return result.status==='pass'?0:result.status==='fail'?1:2;
}
if(process.argv[1]&&fs.realpathSync(process.argv[1])===fs.realpathSync(new URL(import.meta.url)))process.exitCode=main(process.argv.slice(2));
