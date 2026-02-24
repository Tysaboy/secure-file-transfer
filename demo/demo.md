# Demo --- Secure File Transfer

## Step 1 --- Start Server

``` bash
export SECRET526="demo_secret"
python3 src/server.py 22222
```

------------------------------------------------------------------------

## Step 2 --- Start Client

``` bash
export SECRET526="demo_secret"
python3 src/client.py localhost 22222
```

------------------------------------------------------------------------

## Step 3 --- Verify Authentication

Run a basic command:

pwd

Expected: Server responds with current working directory.

Now try starting the client with a different SECRET526 value.

Expected: Authentication fails.

------------------------------------------------------------------------

## Step 4 --- Demonstrate Smart Download Skip

1.  Download a file once.
2.  Download the same file again.

Expected: Second download is skipped because SHA256 hashes match.

------------------------------------------------------------------------

## Step 5 --- Demonstrate Smart Upload Skip

1.  Upload a file.
2.  Upload the same file again.

Expected: Second upload is skipped because SHA256 hashes match.

------------------------------------------------------------------------

## Step 6 --- Integrity Verification

Explain that SHA256 is used to verify file integrity and that Base64
ensures safe transmission over ASCII-based protocol framing.
