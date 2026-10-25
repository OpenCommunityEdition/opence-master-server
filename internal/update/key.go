package update

// ReleaseKey is the public half of the release key (hex), which signs each
// release's SHA256SUMS (cmd/release-sign, in the release workflow). The
// updater installs nothing it does not sign; MASTER_UPDATE_KEY replaces it
// for a fork's releases.
const ReleaseKey = "a61b8ee032e662ff0ba1fc60f60b689343c8893bfa4db6e82f5b791030c6c486"
