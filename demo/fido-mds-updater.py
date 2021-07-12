import json
import os

import webauthn.metadata

MDS_LOCATION = "./fido-mds.json"


def main():
    new_mds = webauthn.metadata.get_metadata()

    if os.path.exists(MDS_LOCATION):
        with open(MDS_LOCATION, "rb") as r:
            old_mds = json.load(r)

        if old_mds["no"] >= new_mds.get("no", 0):
            print("Fetched metadata older or the same as saved copy, ignoring")
            return

    with open(MDS_LOCATION, "w") as r:
        json.dump(new_mds, r)

    print("Metadata updated")


if __name__ == "__main__":
    main()
