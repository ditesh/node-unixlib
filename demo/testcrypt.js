var unixlib = require("../build/Release/unixlib.node");


var res = unixlib.crypt("testpasswd");
console.log("without salt : ",res);

res = unixlib.crypt("testpasswd","12");
console.log("with salt : ",res);

// async call has unpredictable results here
// TODO: fix bugs in cc impl
unixlib.cryptAsync("testpasswd","12",function(){
    console.log("with salt : ", arguments);
  });
unixlib.cryptAsync("testpasswd",function(){
    console.log("without salt : ",arguments);
  });