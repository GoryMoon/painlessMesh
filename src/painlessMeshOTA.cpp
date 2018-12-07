#include <Arduino.h>
#include <ArduinoJson.h>
#include <memory>
#include "painlessMesh.h"

enum otaPacketType {
    OTA_INIT = 0,
    OTA_DATA,
    OTA_FIN,
	OTA_ABORT
};

extern painlessMesh* staticThis;     
     
/* Modified from https://github.com/fcgdam/ESP8266-base64 to handle larger data portions */
const char b64_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                            "abcdefghijklmnopqrstuvwxyz"
                            "0123456789+/";

/* 'Private' declarations */
inline void a3_to_a4(unsigned char * a4, unsigned char * a3);
inline void a4_to_a3(unsigned char * a3, unsigned char * a4);
inline unsigned char b64_lookup(char c);

size_t base64_encode(char *output, char *input, size_t inputLen) {
	size_t i = 0, j = 0;
	size_t encLen = 0;
	unsigned char a3[3];
	unsigned char a4[4];

	while(inputLen--) {
		a3[i++] = *(input++);
		if(i == 3) {
			a3_to_a4(a4, a3);

			for(i = 0; i < 4; i++) {
				output[encLen++] = b64_alphabet[a4[i]];
			}
			i = 0;
		}
	}

	if(i) {
		for(j = i; j < 3; j++) {
			a3[j] = '\0';
		}

		a3_to_a4(a4, a3);

		for(j = 0; j < i + 1; j++) {
			output[encLen++] = b64_alphabet[a4[j]];
		}

		while((i++ < 3)) {
			output[encLen++] = '=';
		}
	}
	output[encLen] = '\0';
	return encLen;
}

size_t base64_decode(char *output, char *input, size_t inputLen) {
	size_t i = 0, j = 0;
	size_t decLen = 0;
	unsigned char a3[3];
	unsigned char a4[4];


	while (inputLen--) {
		if(*input == '=') {
			break;
		}

		a4[i++] = *(input++);
		if (i == 4) {
			for (i = 0; i <4; i++) {
				a4[i] = b64_lookup(a4[i]);
			}

			a4_to_a3(a3,a4);

			for (i = 0; i < 3; i++) {
				output[decLen++] = a3[i];
			}
			i = 0;
		}
	}

	if (i) {
		for (j = i; j < 4; j++) {
			a4[j] = '\0';
		}

		for (j = 0; j <4; j++) {
			a4[j] = b64_lookup(a4[j]);
		}

		a4_to_a3(a3,a4);

		for (j = 0; j < i - 1; j++) {
			output[decLen++] = a3[j];
		}
	}
	output[decLen] = '\0';
	return decLen;
}

size_t base64_enc_len(size_t plainLen) {
	size_t n = plainLen;
	return (n + 2 - ((n + 2) % 3)) / 3 * 4;
}

size_t base64_dec_len(char * input, size_t inputLen) {
	size_t i = 0;
	size_t numEq = 0;
	for(i = inputLen - 1; input[i] == '='; i--) {
		numEq++;
	}

	return ((6 * inputLen) / 8) - numEq;
}

inline void a3_to_a4(unsigned char * a4, unsigned char * a3) {
	a4[0] = (a3[0] & 0xfc) >> 2;
	a4[1] = ((a3[0] & 0x03) << 4) + ((a3[1] & 0xf0) >> 4);
	a4[2] = ((a3[1] & 0x0f) << 2) + ((a3[2] & 0xc0) >> 6);
	a4[3] = (a3[2] & 0x3f);
}

inline void a4_to_a3(unsigned char * a3, unsigned char * a4) {
	a3[0] = (a4[0] << 2) + ((a4[1] & 0x30) >> 4);
	a3[1] = ((a4[1] & 0xf) << 4) + ((a4[2] & 0x3c) >> 2);
	a3[2] = ((a4[2] & 0x3) << 6) + a4[3];
}

inline unsigned char b64_lookup(char c) {
	int i;
	for(i = 0; i < 64; i++) {
		if(b64_alphabet[i] == c) {
			return i;
		}
	}
	return -1;
}

void ICACHE_FLASH_ATTR painlessMesh::handleOTA(std::shared_ptr<MeshConnection> conn, JsonObject& root, bool broadcast) {

    otaPacketType t_ota = (otaPacketType)(int)(root["msg"]["type"]);

    String msg;

    if(t_ota == OTA_INIT) {
        String otaMD5 = root["msg"]["md5"].as<String>();
#ifdef ESP32
		uint32_t maxSketchSpace = 0x140000;
#else		
        uint32_t maxSketchSpace = (ESP.getFreeSketchSpace() - 0x1000) & 0xFFFFF000;
#endif
        Serial.printf("Sketch size %d\n", maxSketchSpace);
        if(Update.isRunning()) {
			Update.end(false);
		}
		staticThis->_otaError = false;
		bool begin = !Update.begin(maxSketchSpace); //start with max available size
        if(begin){
            staticThis->debugMsg(ERROR, "handleOTA(): OTA start failed!\n");
            Update.printError(Serial);
            Update.end();
			staticThis->_otaError = true;
			staticThis->sendOTAError(conn, broadcast);
        }
		if(staticThis->_otaError || !begin) {
			if(!staticThis->_otaError) {
				Update.setMD5(otaMD5.c_str());
			}
			if (!staticThis->_otaError && (!broadcast || _connections.size() <= 1)) {
				staticThis->sendOTAOK(conn, (uint32_t)root["from"], broadcast);
				staticThis->debugMsg(DEBUG, "Sent OK to server\n");
			} else {
				root["msg"].printTo(msg);
				_otaResponses = _connections.size() - 1;
				_otaFromId = (uint32_t)root["from"];
				staticThis->broadcastMessage(_nodeId, OTA_BROADCAST, msg, conn);
			}
        }
    } else if(t_ota == OTA_DATA) {
        const char* b64data = root["msg"]["data"];
        size_t b64len = root["msg"]["length"];

        size_t binlength = base64_dec_len((char*)b64data, b64len);
        uint8_t *b64Data = (uint8_t*)malloc(binlength);

        base64_decode((char*)b64Data, (char*)b64data, b64len); // Decode Base64

		bool write = !staticThis->_otaError && Update.write(b64Data, binlength) != binlength;
        if(write){
            staticThis->debugMsg(ERROR, "handleOTA(): OTA write failed!\n");
            Update.printError(Serial);
            Update.end();
			staticThis->_otaError = true;
			staticThis->sendOTAError(conn, broadcast);
        }
		if(staticThis->_otaError || !write) {
			if (!staticThis->_otaError && (!broadcast || _connections.size() <= 1)) {
				staticThis->sendOTAOK(conn, (uint32_t)root["from"], broadcast);
			} else {
				root["msg"].printTo(msg);
				_otaResponses = _connections.size() - 1;
				_otaFromId = (uint32_t)root["from"];
				staticThis->broadcastMessage(_nodeId, OTA_BROADCAST, msg, conn);
			}
        }
        free(b64Data);
    } else if(t_ota == OTA_FIN) {
		if (broadcast && _connections.size() > 1) {
			root["msg"].printTo(msg);
			staticThis->broadcastMessage(_nodeId, OTA_BROADCAST, msg, conn, true);
		}
		if (staticThis->_otaError) {
			staticThis->_otaError = false;
		} else {
			if(Update.end(true)){ //true to set the size to the current progress
				staticThis->debugMsg(APPLICATION, "handleOTA(): OTA Success!\n");
				rebootTask.enableDelayed(TASK_SECOND * 5);
			} else {
				staticThis->debugMsg(ERROR, "handleOTA(): OTA failed!\n");
				Update.printError(Serial);
			}
		}
    } else if(t_ota == OTA_ABORT) {
		staticThis->_otaError = false;
	}
}

void ICACHE_FLASH_ATTR painlessMesh::sendOTAOK(std::shared_ptr<MeshConnection> conn, uint32_t from, bool broadcast) {
	String msg;
	msg = "OK";
	staticThis->sendMessage(conn, from, _nodeId, broadcast ? OTA_BROADCAST: OTA, msg, true);
}

void ICACHE_FLASH_ATTR painlessMesh::sendOTAError(std::shared_ptr<MeshConnection> conn, bool broadcast) {
	String msg;
	msg = "Error";
	staticThis->_otaError = true;
	if(staticThis->otaUpdateErrorCallback) {
		staticThis->otaUpdateErrorCallback();
	}
	staticThis->sendMessage(conn, 1, _nodeId, broadcast ? OTA_BROADCAST: OTA, msg, true);
}

void ICACHE_FLASH_ATTR painlessMesh::onOtaError(otaUpdateError_t  otaErr) {
	debugMsg(GENERAL, "onOtaError():\n");
    otaUpdateErrorCallback = otaErr;
}

