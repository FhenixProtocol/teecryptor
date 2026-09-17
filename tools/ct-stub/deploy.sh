#!/usr/bin/env bash
# Deploy the ct-stub on a tiny in-VPC VM in teecryptor-tdx, serving the committed
# cofhe corpus over POST /GetCT (:9450) for the on-TDX real-decrypt test.
#
# The Teecryptor TDX VM (same default network) reaches it on its internal IP via
# the default-allow-internal firewall rule. Run from the repo root.
set -euo pipefail
cd "$(dirname "$0")/../.."

PROJECT=${PROJECT:-teecryptor-tdx}
REGION=${REGION:-europe-west4}
ZONE=${ZONE:-europe-west4-b}
BUCKET="${PROJECT}-ctstub"
VM=${VM:-teecryptor-ctstub}

echo "== stage server.py + corpus into a single tarball =="
TMP=$(mktemp -d)
mkdir -p "$TMP/pkg/corpus"
cp tools/ct-stub/server.py "$TMP/pkg/server.py"
cp tests/cofhe_compat/manifest.json tests/cofhe_compat/*.ct "$TMP/pkg/corpus/"
tar czf "$TMP/ctstub.tgz" -C "$TMP/pkg" .

echo "== bucket + upload =="
gcloud storage buckets create "gs://$BUCKET" --project="$PROJECT" --location="$REGION" \
  --uniform-bucket-level-access 2>/dev/null || echo "  bucket exists"
gcloud storage cp "$TMP/ctstub.tgz" "gs://$BUCKET/ctstub.tgz"

echo "== grant the VM's default SA read on the bucket =="
NUM=$(gcloud projects describe "$PROJECT" --format='value(projectNumber)')
SA="${NUM}-compute@developer.gserviceaccount.com"
gcloud storage buckets add-iam-policy-binding "gs://$BUCKET" \
  --member="serviceAccount:$SA" --role=roles/storage.objectViewer >/dev/null

echo "== create the e2-micro stub VM (Debian 12; python3 preinstalled) =="
# Downloads via curl + the metadata SA token (no gcloud-on-VM dependency).
# External IP only for egress to storage.googleapis.com; no ingress opened
# beyond the default network's allow-internal (how the TDX VM reaches :9450).
# Write the startup script to a file and pass via --metadata-from-file so gcloud
# doesn't split the body on the commas/'='/';' inside it.
cat >"$TMP/startup.sh" <<EOS
#!/bin/bash
set -e
mkdir -p /opt/ctstub
TOKEN=\$(curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
curl -s -H "Authorization: Bearer \$TOKEN" "https://storage.googleapis.com/storage/v1/b/${BUCKET}/o/ctstub.tgz?alt=media" -o /opt/ctstub/ctstub.tgz
tar xzf /opt/ctstub/ctstub.tgz -C /opt/ctstub
cat >/etc/systemd/system/ctstub.service <<UNIT
[Unit]
Description=cofhe ct-stub
After=network-online.target
[Service]
Environment=CORPUS_DIR=/opt/ctstub/corpus
Environment=PORT=9450
ExecStart=/usr/bin/python3 /opt/ctstub/server.py
Restart=always
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now ctstub
EOS

gcloud compute instances create "$VM" \
  --project="$PROJECT" --zone="$ZONE" \
  --machine-type=e2-micro --network=default \
  --image-family=debian-12 --image-project=debian-cloud \
  --scopes=cloud-platform \
  --metadata-from-file=startup-script="$TMP/startup.sh" 2>&1 | tail -3

IP=$(gcloud compute instances describe "$VM" --project="$PROJECT" --zone="$ZONE" \
  --format='value(networkInterfaces[0].networkIP)')
echo
echo "== ct-stub internal IP: $IP =="
echo "   set in compute/terraform.tfvars:  ct_source_url = \"http://$IP:9450\""
