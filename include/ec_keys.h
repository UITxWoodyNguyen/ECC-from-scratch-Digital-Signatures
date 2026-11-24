#pragma once

#include "common.h"

bool generateKeyPair(const string &algName, EvpPkeyPtr &outKey);
bool loadStrictKey(const string &filePath, bool isPrivate, EvpPkeyPtr &outKey, string &errReason);

bool isAllowedAlgorithm(const string &algName);
string normalizeAlgName(const string &algName);
string getKeyAlgorithmName(EVP_PKEY *key);
string getKeyCurveName(EVP_PKEY *key);
int getKeySecurityLevel(EVP_PKEY *key);
Bytes getPublicKeyRepresentation(EVP_PKEY *key);

int handleKeyGen(int argc, char **argv);
int handleKeyInfo(int argc, char **argv);
int handleKeyCheck(int argc, char **argv);
int handlePubImport(int argc, char **argv);
