#pragma once

#include "common.h"

Bytes x25519MontgomeryLadder(const Bytes &scalar, const Bytes &uCoord);
int handleX25519SelfTest();
int handleEcdhSelfTest(int argc, char **argv);
