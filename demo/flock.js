var fs = require("fs");
var unixlib = require("../build/default/unixlib");
var filename = "/tmp/flock.example";

// Let's try flocking
fs.open(filename, "r", undefined, function(err, fd) {

	if (err === null) {

		unixlib.flock(fd, function(result) {
			console.log(result);
		});
	}
});
