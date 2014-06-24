{
  "targets": [
    {
      "target_name": "unixlib",
      "include_dirs": [ "security/pam_appl.h","crypt.h" ],
      "direct_dependent_settings": {
        "linkflags": [ "-lpam", "-lcrypt" ]
      },
      'link_settings': {
        'libraries': ["-lpam", "-lcrypt"],
      },

      "conditions": [
		[ "OS=='win'", {
		
		}, { # OS != win
          "cflags": [ "-g", "-D_FILE_OFFSET_BITS=64", "-D_LARGEFILE_SOURCE", "-Wall" ]
        }
      ] ],
      "sources": [ "unixlib.cc" ]
    }
  ]
}