import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';

// Tiny valid manually encoded WebAssembly modules; no Rust compiler required.
const provider = Buffer.from('0061736d0100000001060160017f017f03020100070a010673717561726500000a09010700200020006c0b','hex');
const consumer = Buffer.from('0061736d0100000001060160017f017f020e0103656e7606737175617265000003020100070b0107636f6d7075746500010a0b0109002000100041016a0b','hex');
const sha = b => createHash('sha256').update(b).digest('hex');
async function test(order) {
  const available = new Map(), ready = new Map();
  for (const [name,bytes] of order) {
    const module = await WebAssembly.compile(bytes);
    available.set(name,{module,imports:WebAssembly.Module.imports(module),exports:WebAssembly.Module.exports(module),digest:sha(bytes)});
    let changed = true;
    while (changed) {
      changed = false;
      for (const [key,item] of available) {
        if (ready.has(key)) continue;
        const bindings={}; let blocked=false;
        for(const imp of item.imports) {
          const providers=[...ready.values()].filter(x=>x.exports.some(e=>e.name===imp.name && e.kind===imp.kind));
          if(providers.length!==1) {blocked=true;break;}
          (bindings[imp.module]??={})[imp.name]=providers[0].instance.exports[imp.name];
        }
        if(blocked) continue;
        const instance=await WebAssembly.instantiate(item.module,bindings);
        ready.set(key,{instance,exports:item.exports});changed=true;
      }
    }
  }
  assert.equal(ready.size,2);
  assert.equal(ready.get('consumer').instance.exports.compute(7),50);
  return Object.fromEntries([...available].map(([name,x])=>[name,{bytes:name==='provider'?provider.length:consumer.length,sha256:x.digest,imports:x.imports,exports:x.exports}]));
}
console.log(JSON.stringify({
  consumerFirst:await test([['consumer',consumer],['provider',provider]]),
  providerFirst:await test([['provider',provider],['consumer',consumer]]),
  result:50
},null,2));
