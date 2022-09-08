

const {
    GREASE_TABLE
} = require("./tls-info");
const md5 = require("./md5");

class Parser {
    constructor(buffer) {
        this.buffer = buffer;
        //console.log("buffer bytelegt: " + buffer.byteLength);
        this.offset = 0;
        this.things = []

        this._TLS_VERSION = null;
        this._TLS_CIPHERS = [];
        this._TLS_EXTENSIONS = [];
        this._TLS_ELLIPTIC_CURVES = [];
        this._ELLIPTIC_CURVE_POINT_FORMATS = [];

        this.RecordHeader();
        this.HandShakeHeader();
        this.ClientVersion();
        this.ClientRandom();
        this.SessionId();
        this.CipherSuites();
        this.CompressionMethod();
        this.ExtensionLength();
        console.log(this.generateHash());
    }

    RecordHeader() {
        let type = this.buffer.readUint8(this.offset++);
        let v_major = this.buffer.readUint8(this.offset++);
        let v_minor = this.buffer.readUint8(this.offset++);
        let version = `${v_major}.${v_minor}`;
        console.log("TLS VERSION: " + version);
        let size = (this.buffer.readUint8(this.offset++) << 8) | this.buffer.readUint8(this.offset++);
        //console.log("type: " + type, "version: " + version, "size: " + size);
    }

    HandShakeHeader() {
        let handshakeMessage = this.buffer.readUint8(this.offset++);
        let bytes = (this.buffer.readUint8(this.offset++) << 16) | (this.buffer.readUint8(this.offset++) << 8) | (this.buffer.readUint8(this.offset++));
        //console.log("message: " + handshakeMessage, "size: " + bytes);
    }

    ClientVersion() {
        let v_major = this.buffer.readUint8(this.offset++);
        let v_minor = this.buffer.readUint8(this.offset++);
        let clientVersion = `${v_major}.${v_minor}`;
        this._TLS_VERSION = (v_major << 8) | v_minor;
        //console.log("client version: " + clientVersion);
    }

    ClientRandom() {
        let bytes = new Uint8Array(32);
        for (let i = 0; i < 32; i++) {
            bytes[i] = this.buffer.readUint8(this.offset++);
        }
    }

    SessionId() {
        let sessionId = this.buffer.readUint8(this.offset++);
        let bytes = new Uint8Array(sessionId);
        for (let i = 0; i < sessionId; i++) {
            bytes[i] = this.buffer.readUint8(this.offset++);
        }
        //console.log(sessionId, "sessionid");
    }

    CipherSuites() {
        let cipherBytes = (this.buffer.readUint8(this.offset++) << 8) | this.buffer.readUint8(this.offset++);
        //console.log("Using N cipherSuites: " + cipherBytes);
        for (let i = 0; i < cipherBytes * .5; i++) {
            let cipherName = (this.buffer.readUint8(this.offset++) << 8) | this.buffer.readUint8(this.offset++);
            if (!GREASE_TABLE[cipherName]) {
                this._TLS_CIPHERS.push(cipherName);
                this.things.push(cipherName);
            }else{
                //console.log(cipherName);
            }
        }
    }

    CompressionMethod() {
        let method = this.buffer.readUint8(this.offset++);
        let nullAssigned = this.buffer.readUint8(this.offset++);
        //console.log("method: " + method, "should be zero: " + nullAssigned);
    }

    ExtensionLength() {
        let extensionByteLength = (this.buffer.readUint8(this.offset++) << 8) | this.buffer.readUint8(this.offset++);
        let start = this.offset;

        while (this.offset < start + extensionByteLength) {
            let extensionName = (this.buffer.readUint8(this.offset++) << 8) | this.buffer.readUint8(this.offset++);
            let extensionLength = (this.buffer.readUint8(this.offset++) << 8) | this.buffer.readUint8(this.offset++);
            let _start = this.offset;

            switch(extensionName){
                case 0x0a: {

                    let bytes = (this.buffer.readUint8(this.offset++) << 8) | this.buffer.readUint8(this.offset++);
                    for(let i = 0; i < bytes; i += 2){
                        let curve = (this.buffer.readUint8(this.offset++) << 8) | this.buffer.readUint8(this.offset++);
                        //console.log("curve:", curve);
                        if(!GREASE_TABLE[curve]) this._TLS_ELLIPTIC_CURVES.push(curve);
                   //     else console.log("Unknwon curve Type: " + curve);
                    }

                    break;
                }
                case 0xB: {
                    let bytes = (this.buffer.readUint8(this.offset++));
                   // console.log("CURVED?", bytes);
                    for(let i = 0 ; i < bytes; i++){
                        let curve = (this.buffer.readUint8(this.offset++));
                        this._ELLIPTIC_CURVE_POINT_FORMATS.push(curve);
                    }
                    break;
                }
            }

            this.offset = _start + extensionLength;

            if (!GREASE_TABLE[extensionName]) {
                this._TLS_EXTENSIONS.push(extensionName);
                this.things.push(extensionName);
            }else{
               // console.log("Unknwon Extension: " + extensionName);
            }
        }
        //throw(1000);
    }

    generateHash() {
        let data = this._TLS_VERSION + "," + this._TLS_CIPHERS.join("-") + "," + this._TLS_EXTENSIONS.join("-") + "," + this._TLS_ELLIPTIC_CURVES.join("-") + "," + this._ELLIPTIC_CURVE_POINT_FORMATS.join("-");
        console.log(data);
        return md5(data);
    }
}

module.exports = Parser;