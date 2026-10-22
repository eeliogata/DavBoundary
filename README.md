# DavBoundary

Check whether WebDAV `COPY` or `MOVE` can write into a collection when the acting user cannot `PUT` there. The tool creates unique files in an actor-writable source collection and an owner-writable destination collection, then reads the destination as the owner after each operation.

Requires Python 3. Put each identity's HTTP headers in a local JSON object, such as `{"Authorization":"Bearer ..."}`. The header files are not copied into the report.

```sh
python3 davboundary.py --origin https://dav.example --source /dav/actor/ --destination /dav/owner/ --actor-headers actor.json --owner-headers owner.json --out result.json
```

The run checks direct `PUT` to the destination, then `COPY` and `MOVE` with `Overwrite: F` into new paths and `Overwrite: T` into owner-created paths. The report contains statuses, ETags, body hashes, source state after each method, and owner-side readback. `destination_write_after_failed_put` is true only when the direct `PUT` control failed and an operation's actor payload appeared at the destination. Status codes alone are not treated as proof of a write.

Cleanup deletes only paths with the content written by this run. If a path contains other data, it is left in place and the command exits with status 2. Use collections where both identities can read their own files and where the owner can delete the tool's destination files.
