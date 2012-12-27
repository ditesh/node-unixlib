var unixlib = require("../build/Release/unixlib.node");

unixlib.crypt("testpasswd","12",function(){
    console.log("with salt : ", arguments);
  });
  
unixlib.crypt("testpasswd",function(){
    console.log("without salt : ",arguments);
  });