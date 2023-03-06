```sh
gcc webserver.c base64.c -l crypto
```

Creates a webserver that listens on port 8080 and serves the `index.html` file. Should accept websocket upgrade http packet; probably doesnt :-). Callum plz fix.
