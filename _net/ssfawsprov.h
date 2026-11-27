/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfawsprov.h                                                                                  */
/* AWS IoT Core Fleet Provisioning over MQTT (CreateCertificateFromCsr, RegisterThing).          */
/*                                                                                               */
/* BSD-3-Clause License                                                                          */
/* Copyright 2026 Supurloop Software LLC                                                         */
/*                                                                                               */
/* Redistribution and use in source and binary forms, with or without modification, are          */
/* permitted provided that the following conditions are met:                                     */
/*                                                                                               */
/* 1. Redistributions of source code must retain the above copyright notice, this list of        */
/* conditions and the following disclaimer.                                                      */
/* 2. Redistributions in binary form must reproduce the above copyright notice, this list of     */
/* conditions and the following disclaimer in the documentation and/or other materials provided  */
/* with the distribution.                                                                        */
/* 3. Neither the name of the copyright holder nor the names of its contributors may be used to  */
/* endorse or promote products derived from this software without specific prior written         */
/* permission.                                                                                   */
/*                                                                                               */
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS   */
/* OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF               */
/* MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE    */
/* COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL      */
/* EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE */
/* GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED    */
#ifndef SSF_AWSPROV_H_INCLUDE
#define SSF_AWSPROV_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include "ssfport.h"

/* --------------------------------------------------------------------------------------------- */
/* Defines                                                                                       */
/* --------------------------------------------------------------------------------------------- */
/* Template name size with NUL; AWS allows 1..36 characters of [0-9A-Za-z_-] */
#define SSF_AWSPROV_TEMPLATE_NAME_SIZE (37u)

/* Longest topic size with NUL: $aws/provisioning-templates/<36>/provision/json/rejected */
#define SSF_AWSPROV_MAX_TOPIC_SIZE (89u)

#if SSF_MQTTC_CONFIG_MAX_TOPIC_SIZE < SSF_AWSPROV_MAX_TOPIC_SIZE
#error SSF_MQTTC_CONFIG_MAX_TOPIC_SIZE must be at least SSF_AWSPROV_MAX_TOPIC_SIZE.
#endif
#if SSF_MQTTC_CONFIG_MAX_CLIENT_ID_SIZE < SSF_AWSPROV_CONFIG_THING_NAME_SIZE
#error SSF_MQTTC_CONFIG_MAX_CLIENT_ID_SIZE must be at least SSF_AWSPROV_CONFIG_THING_NAME_SIZE.
#endif
#if SSF_JSON_CONFIG_MAX_IN_LEN < (SSF_AWSPROV_CONFIG_RX_SIZE - 1u)
#error SSF_JSON_CONFIG_MAX_IN_LEN must be at least SSF_AWSPROV_CONFIG_RX_SIZE - 1.
#endif

/* --------------------------------------------------------------------------------------------- */
/* Unit test                                                                                     */
/* --------------------------------------------------------------------------------------------- */
#if SSF_CONFIG_AWSPROV_UNIT_TEST == 1
void SSFAWSProvUnitTest(void);
#endif /* SSF_CONFIG_AWSPROV_UNIT_TEST */

#ifdef __cplusplus
}
#endif

#endif /* SSF_AWSPROV_H_INCLUDE */
