var fs = require("fs");
var unixlib = require("unix");
var filename = "/tmp/somefile";

fs.open(filename, "r", function(err, fd) {

	// This should work
	unixlib.flock(fd, function(result) {

		if (result) {

			console.log("File has been successfully flocked");

			// This should not work
			unixlib.flock(fd, function(result) {

				if (result)
					console.log("File has been successfully flocked, against our most sincere expectations");
				else
					console.log("File cannot be flocked, as we expected");

			});

		} else {

			
			console.log("For some reason, couldn't flock");

		}
	});
});
