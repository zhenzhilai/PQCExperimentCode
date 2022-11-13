/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.c
  * @brief          : Main program body
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2022 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
/* USER CODE END Header */
/* Includes ------------------------------------------------------------------*/
#include "main.h"
#include "usart.h"
#include "gpio.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
#include "XMF_OLED_STM32Cube.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "params.h"
#include "kem.h"
#include "kex.h"
#include "indcpa.h"
#include "verify.h"
#include "symmetric.h"
#include "randombytes.h"

#include "cmox_crypto.h"

/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */
/* Global variables ----------------------------------------------------------*/

cmox_ecc_handle_t Ecc_Ctx;


/* RSA context */
cmox_rsa_handle_t Rsa_Ctx;
/* RSA key */
cmox_rsa_key_t Rsa_Key;

/* RSA working buffer */
uint8_t Working_Buffer[7000];

//const uint8_t Message[] =
//{
//  0xbc, 0xdd, 0x19, 0x0d, 0xa3, 0xb7, 0xd3, 0x00, 0xdf, 0x9a, 0x06, 0xe2, 0x2c, 0xaa, 0xe2, 0xa7,
//  0x5f, 0x10, 0xc9, 0x1f, 0xf6, 0x67, 0xb7, 0xc1, 0x6b, 0xde, 0x8b, 0x53, 0x06, 0x4a, 0x26, 0x49,
//  0xa9, 0x40, 0x45, 0xc9
//};

const uint8_t Message[] =
{
  0x5f, 0x10, 0xc9, 0x1f, 0xf6, 0x67, 0xa9, 0x40, 0x45, 0xc9, 0xa9, 0x40, 0x45, 0xc9, 0x26, 0x49,
  0x5f, 0x10, 0xc9, 0x1f, 0xf6, 0x67, 0xb7, 0xc1, 0x6b, 0xde, 0x8b, 0x53, 0x06, 0x4a, 0x26, 0x49
};


const uint8_t Seed[] =
{
  0x5c, 0xac, 0xa6, 0xa0, 0xf7, 0x64, 0x16, 0x1a, 0x96, 0x84, 0xf8, 0x5d, 0x92, 0xb6, 0xe0, 0xef,
  0x37, 0xca, 0x8b, 0x65
};

const uint8_t Modulus[] =
{
  0xae, 0x45, 0xed, 0x56, 0x01, 0xce, 0xc6, 0xb8, 0xcc, 0x05, 0xf8, 0x03, 0x93, 0x5c, 0x67, 0x4d,
  0xdb, 0xe0, 0xd7, 0x5c, 0x4c, 0x09, 0xfd, 0x79, 0x51, 0xfc, 0x6b, 0x0c, 0xae, 0xc3, 0x13, 0xa8,
  0xdf, 0x39, 0x97, 0x0c, 0x51, 0x8b, 0xff, 0xba, 0x5e, 0xd6, 0x8f, 0x3f, 0x0d, 0x7f, 0x22, 0xa4,
  0x02, 0x9d, 0x41, 0x3f, 0x1a, 0xe0, 0x7e, 0x4e, 0xbe, 0x9e, 0x41, 0x77, 0xce, 0x23, 0xe7, 0xf5,
  0x40, 0x4b, 0x56, 0x9e, 0x4e, 0xe1, 0xbd, 0xcf, 0x3c, 0x1f, 0xb0, 0x3e, 0xf1, 0x13, 0x80, 0x2d,
  0x4f, 0x85, 0x5e, 0xb9, 0xb5, 0x13, 0x4b, 0x5a, 0x7c, 0x80, 0x85, 0xad, 0xca, 0xe6, 0xfa, 0x2f,
  0xa1, 0x41, 0x7e, 0xc3, 0x76, 0x3b, 0xe1, 0x71, 0xb0, 0xc6, 0x2b, 0x76, 0x0e, 0xde, 0x23, 0xc1,
  0x2a, 0xd9, 0x2b, 0x98, 0x08, 0x84, 0xc6, 0x41, 0xf5, 0xa8, 0xfa, 0xc2, 0x6b, 0xda, 0xd4, 0xa0,
  0x33, 0x81, 0xa2, 0x2f, 0xe1, 0xb7, 0x54, 0x88, 0x50, 0x94, 0xc8, 0x25, 0x06, 0xd4, 0x01, 0x9a,
  0x53, 0x5a, 0x28, 0x6a, 0xfe, 0xb2, 0x71, 0xbb, 0x9b, 0xa5, 0x92, 0xde, 0x18, 0xdc, 0xf6, 0x00,
  0xc2, 0xae, 0xea, 0xe5, 0x6e, 0x02, 0xf7, 0xcf, 0x79, 0xfc, 0x14, 0xcf, 0x3b, 0xdc, 0x7c, 0xd8,
  0x4f, 0xeb, 0xbb, 0xf9, 0x50, 0xca, 0x90, 0x30, 0x4b, 0x22, 0x19, 0xa7, 0xaa, 0x06, 0x3a, 0xef,
  0xa2, 0xc3, 0xc1, 0x98, 0x0e, 0x56, 0x0c, 0xd6, 0x4a, 0xfe, 0x77, 0x95, 0x85, 0xb6, 0x10, 0x76,
  0x57, 0xb9, 0x57, 0x85, 0x7e, 0xfd, 0xe6, 0x01, 0x09, 0x88, 0xab, 0x7d, 0xe4, 0x17, 0xfc, 0x88,
  0xd8, 0xf3, 0x84, 0xc4, 0xe6, 0xe7, 0x2c, 0x3f, 0x94, 0x3e, 0x0c, 0x31, 0xc0, 0xc4, 0xa5, 0xcc,
  0x36, 0xf8, 0x79, 0xd8, 0xa3, 0xac, 0x9d, 0x7d, 0x59, 0x86, 0x0e, 0xaa, 0xda, 0x6b, 0x83, 0xbb
};
const uint8_t Public_Exponent[] =
{
  0x01, 0x00, 0x01
};
const uint8_t Private_Exponent[] =
{
  0x05, 0x6b, 0x04, 0x21, 0x6f, 0xe5, 0xf3, 0x54, 0xac, 0x77, 0x25, 0x0a, 0x4b, 0x6b, 0x0c, 0x85,
  0x25, 0xa8, 0x5c, 0x59, 0xb0, 0xbd, 0x80, 0xc5, 0x64, 0x50, 0xa2, 0x2d, 0x5f, 0x43, 0x8e, 0x59,
  0x6a, 0x33, 0x3a, 0xa8, 0x75, 0xe2, 0x91, 0xdd, 0x43, 0xf4, 0x8c, 0xb8, 0x8b, 0x9d, 0x5f, 0xc0,
  0xd4, 0x99, 0xf9, 0xfc, 0xd1, 0xc3, 0x97, 0xf9, 0xaf, 0xc0, 0x70, 0xcd, 0x9e, 0x39, 0x8c, 0x8d,
  0x19, 0xe6, 0x1d, 0xb7, 0xc7, 0x41, 0x0a, 0x6b, 0x26, 0x75, 0xdf, 0xbf, 0x5d, 0x34, 0x5b, 0x80,
  0x4d, 0x20, 0x1a, 0xdd, 0x50, 0x2d, 0x5c, 0xe2, 0xdf, 0xcb, 0x09, 0x1c, 0xe9, 0x99, 0x7b, 0xbe,
  0xbe, 0x57, 0x30, 0x6f, 0x38, 0x3e, 0x4d, 0x58, 0x81, 0x03, 0xf0, 0x36, 0xf7, 0xe8, 0x5d, 0x19,
  0x34, 0xd1, 0x52, 0xa3, 0x23, 0xe4, 0xa8, 0xdb, 0x45, 0x1d, 0x6f, 0x4a, 0x5b, 0x1b, 0x0f, 0x10,
  0x2c, 0xc1, 0x50, 0xe0, 0x2f, 0xee, 0xe2, 0xb8, 0x8d, 0xea, 0x4a, 0xd4, 0xc1, 0xba, 0xcc, 0xb2,
  0x4d, 0x84, 0x07, 0x2d, 0x14, 0xe1, 0xd2, 0x4a, 0x67, 0x71, 0xf7, 0x40, 0x8e, 0xe3, 0x05, 0x64,
  0xfb, 0x86, 0xd4, 0x39, 0x3a, 0x34, 0xbc, 0xf0, 0xb7, 0x88, 0x50, 0x1d, 0x19, 0x33, 0x03, 0xf1,
  0x3a, 0x22, 0x84, 0xb0, 0x01, 0xf0, 0xf6, 0x49, 0xea, 0xf7, 0x93, 0x28, 0xd4, 0xac, 0x5c, 0x43,
  0x0a, 0xb4, 0x41, 0x49, 0x20, 0xa9, 0x46, 0x0e, 0xd1, 0xb7, 0xbc, 0x40, 0xec, 0x65, 0x3e, 0x87,
  0x6d, 0x09, 0xab, 0xc5, 0x09, 0xae, 0x45, 0xb5, 0x25, 0x19, 0x01, 0x16, 0xa0, 0xc2, 0x61, 0x01,
  0x84, 0x82, 0x98, 0x50, 0x9c, 0x1c, 0x3b, 0xf3, 0xa4, 0x83, 0xe7, 0x27, 0x40, 0x54, 0xe1, 0x5e,
  0x97, 0x07, 0x50, 0x36, 0xe9, 0x89, 0xf6, 0x09, 0x32, 0x80, 0x7b, 0x52, 0x57, 0x75, 0x1e, 0x79
};

const uint8_t Modulus_3072[] =
{
  0xbd, 0xba, 0xf0, 0xc9, 0x69, 0x2d, 0xc8, 0x25, 0xcf, 0x50, 0x8c, 0xd4, 0xc4, 0x75, 0xb4, 0xe8,
  0xb7, 0xb1, 0xb1, 0xbd, 0x25, 0x3d, 0x74, 0xde, 0xfb, 0xe2, 0x61, 0xf2, 0xf7, 0x0f, 0xe4, 0xa6,
  0x8e, 0x5b, 0xdb, 0x1c, 0xc9, 0xd2, 0x7e, 0x7c, 0x5a, 0x9f, 0x0c, 0x06, 0x85, 0x67, 0xc4, 0x12,
  0x70, 0x53, 0xf8, 0xb7, 0xda, 0xb1, 0xd4, 0xc7, 0xfa, 0x3c, 0xaa, 0xfd, 0x82, 0x5a, 0x0a, 0x25,
  0xde, 0x70, 0x77, 0xd0, 0xf3, 0xb1, 0x10, 0x80, 0x62, 0x5a, 0x9f, 0xf1, 0x7b, 0x0b, 0x71, 0x2b,
  0x29, 0xf7, 0xa6, 0x3f, 0xf9, 0x59, 0x57, 0x0d, 0xf0, 0x66, 0x72, 0xb1, 0xba, 0xa8, 0x62, 0x10,
  0x07, 0xff, 0x84, 0xdf, 0x6f, 0xf9, 0x72, 0x38, 0x05, 0x1c, 0x96, 0xf2, 0x34, 0x3a, 0x32, 0x4c,
  0x99, 0x86, 0xde, 0xdd, 0x17, 0xc8, 0x2a, 0x68, 0x30, 0x9d, 0xb6, 0xfe, 0x34, 0x08, 0x2e, 0x26,
  0x84, 0x69, 0x36, 0xb5, 0x75, 0x24, 0x59, 0x81, 0x08, 0x5a, 0x5e, 0xef, 0x3a, 0xa1, 0x09, 0x94,
  0x6a, 0xa4, 0x30, 0x4e, 0x0c, 0x8f, 0xca, 0x9f, 0xfc, 0xc6, 0x56, 0xb8, 0xb5, 0x41, 0x85, 0xc7,
  0xbd, 0x74, 0xc4, 0xfe, 0xe9, 0xef, 0x70, 0xec, 0xca, 0x60, 0x58, 0xce, 0xf5, 0x65, 0x04, 0xa8,
  0xb8, 0x6e, 0x06, 0x4e, 0x17, 0x57, 0x73, 0x63, 0x1d, 0x2f, 0x87, 0xb1, 0xe1, 0x29, 0xf3, 0x5a,
  0x92, 0xf0, 0x6e, 0xad, 0x29, 0xc9, 0xc7, 0xb5, 0x05, 0xa4, 0x13, 0xd1, 0xa6, 0x7e, 0x59, 0xc8,
  0x35, 0x8a, 0x0e, 0xbd, 0x23, 0x47, 0x9b, 0x50, 0x5c, 0xb9, 0xcd, 0x73, 0xe9, 0x0f, 0x64, 0xef,
  0x44, 0xcb, 0xdd, 0x46, 0x04, 0xfe, 0x2b, 0x6e, 0x07, 0x2e, 0xa4, 0xb6, 0x3d, 0x41, 0xb9, 0x6d,
  0xea, 0x0f, 0x6b, 0xff, 0x6f, 0x19, 0x97, 0xa9, 0x7a, 0x43, 0x48, 0x50, 0x94, 0x02, 0xae, 0x7d,
  0x8b, 0x2f, 0x15, 0x7e, 0xac, 0x30, 0xd6, 0xa4, 0xd9, 0xae, 0x22, 0x0e, 0xe1, 0x87, 0xe5, 0xda,
  0xb4, 0xee, 0x51, 0xbb, 0xd2, 0xb2, 0xad, 0x06, 0xab, 0x04, 0xeb, 0xc2, 0xfc, 0xbb, 0xcc, 0xf5,
  0xcb, 0x23, 0x8a, 0x2f, 0xb3, 0x1a, 0xd1, 0xb0, 0xb6, 0x14, 0xbb, 0x97, 0xe0, 0x1d, 0x21, 0x1a,
  0x37, 0xac, 0x02, 0x58, 0x2b, 0x5c, 0x10, 0x59, 0x78, 0x8b, 0xb1, 0x14, 0x5f, 0x91, 0x42, 0xae,
  0x50, 0x02, 0x1d, 0x73, 0x77, 0x29, 0x94, 0x98, 0xa2, 0xab, 0x68, 0x45, 0x23, 0x53, 0xb2, 0x17,
  0x46, 0x0b, 0xad, 0xfd, 0xef, 0x60, 0x14, 0x56, 0xfb, 0xfa, 0xe3, 0x2e, 0x08, 0xa5, 0x59, 0x2b,
  0x4e, 0x42, 0x10, 0x55, 0x9a, 0x57, 0x68, 0x68, 0x20, 0xc7, 0xf4, 0x98, 0x75, 0x0d, 0x34, 0x5f,
  0xf4, 0xa9, 0x23, 0xd7, 0x2c, 0x4a, 0xe3, 0x4b, 0xd7, 0x73, 0xd4, 0xa6, 0xd6, 0xe7, 0xd1, 0x69
};

const uint8_t Private_Exponent_3072[] =
{
  0x57, 0x07, 0x9f, 0x57, 0xe4, 0x45, 0x39, 0xe0, 0x0e, 0x1e, 0xd6, 0xda, 0xea, 0x5b, 0x4b, 0xe6,
  0xcc, 0x0c, 0x58, 0x89, 0x78, 0xc1, 0x9e, 0x10, 0x82, 0xde, 0x2f, 0x2b, 0xf2, 0x24, 0x7a, 0x2f,
  0xe4, 0x71, 0x42, 0x2b, 0x0c, 0x70, 0xdf, 0xd0, 0x4f, 0x09, 0x51, 0xcc, 0xd3, 0xf8, 0xeb, 0x39,
  0xc2, 0x08, 0xe2, 0xb8, 0x03, 0x3b, 0x3b, 0x6d, 0x97, 0xdd, 0xa8, 0x59, 0xad, 0x27, 0x7c, 0x2c,
  0x2e, 0xc2, 0xcc, 0x53, 0x2e, 0xd5, 0x73, 0xca, 0x50, 0x53, 0x5d, 0xb6, 0xb9, 0x48, 0x60, 0x5a,
  0xfa, 0x5f, 0x3d, 0x05, 0x6f, 0x6d, 0x89, 0xbf, 0x3d, 0x1c, 0xe1, 0x53, 0xa1, 0x59, 0x87, 0xd1,
  0xee, 0xb9, 0x48, 0xcb, 0xed, 0x63, 0x30, 0xff, 0x7d, 0x68, 0xc5, 0xdc, 0xc8, 0x14, 0x41, 0xea,
  0x5d, 0x2a, 0x3e, 0xa4, 0x90, 0x3a, 0x23, 0x29, 0xb3, 0xd3, 0x44, 0x93, 0x8a, 0x6e, 0x8e, 0x2c,
  0xe0, 0xe4, 0x1a, 0x52, 0x56, 0x2f, 0x9c, 0x56, 0xd1, 0xec, 0x12, 0x4c, 0x0e, 0x4a, 0xbc, 0x48,
  0x36, 0x3a, 0xa6, 0x65, 0xc6, 0xe1, 0x56, 0x82, 0xd8, 0xc2, 0x6a, 0x19, 0x44, 0x1b, 0x90, 0x30,
  0x35, 0x39, 0x90, 0xfb, 0x95, 0x77, 0x5e, 0x07, 0x60, 0x35, 0x9d, 0xc7, 0x21, 0x4d, 0x7b, 0x3b,
  0xa1, 0x8d, 0xe6, 0x9a, 0x7f, 0x9e, 0x7f, 0xb1, 0x61, 0x3b, 0xe2, 0x34, 0xb8, 0x22, 0x34, 0x1b,
  0xf7, 0x2a, 0x95, 0x2d, 0x9a, 0x12, 0xfd, 0x2c, 0x83, 0x2c, 0xe3, 0x2f, 0xff, 0xcb, 0x19, 0xba,
  0x99, 0xc5, 0xc1, 0x5a, 0x5e, 0x41, 0x1f, 0x5c, 0x51, 0x72, 0x9d, 0x11, 0xa6, 0xcc, 0xb9, 0x75,
  0x90, 0x47, 0x24, 0xfe, 0xa1, 0x43, 0x97, 0x60, 0x40, 0x07, 0x49, 0xf6, 0xc0, 0x5c, 0x38, 0x0d,
  0x63, 0x1c, 0x94, 0xf3, 0x3e, 0x59, 0xab, 0x3c, 0x42, 0x27, 0xa6, 0x32, 0x14, 0x9c, 0xdc, 0xc4,
  0xde, 0x9c, 0xf2, 0x05, 0xc2, 0x5a, 0x5d, 0x70, 0x60, 0x61, 0x55, 0x2f, 0xc7, 0xe8, 0x2f, 0x27,
  0x0e, 0x25, 0x07, 0x19, 0x73, 0xab, 0x36, 0xe1, 0x8c, 0x65, 0xc3, 0x6e, 0x24, 0x4f, 0x1a, 0x00,
  0x18, 0xa7, 0xeb, 0x99, 0xbe, 0x84, 0x73, 0x68, 0x2a, 0x53, 0x68, 0x3c, 0xde, 0x45, 0x6c, 0x19,
  0xff, 0x73, 0x6f, 0x8a, 0xfe, 0x11, 0x2a, 0x43, 0x36, 0x9c, 0xfe, 0x0d, 0xc0, 0x0f, 0xdb, 0x50,
  0xbd, 0x9c, 0xe6, 0xd4, 0x2e, 0x82, 0x59, 0xf3, 0xf9, 0x2d, 0x4b, 0xd7, 0x20, 0x9a, 0x95, 0x42,
  0x8c, 0x3e, 0x20, 0x4b, 0x69, 0xf2, 0x7e, 0x1b, 0x9e, 0x1b, 0xc2, 0x5e, 0x73, 0xfd, 0x4e, 0xe4,
  0xa9, 0x04, 0x00, 0x62, 0x33, 0x0e, 0x9e, 0x0a, 0x7f, 0xd8, 0xb1, 0x73, 0x91, 0x61, 0x4d, 0xe1,
  0x97, 0xd4, 0x27, 0xa5, 0x9d, 0x5d, 0xd1, 0x73, 0x48, 0xdf, 0x2f, 0xf8, 0x09, 0xe5, 0x29, 0x01
};

/* Computed data buffer */
uint8_t Computed_Encryption[384];
uint8_t Computed_Text[sizeof(Message)];

/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */
/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/

/* USER CODE BEGIN PV */

/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
/* USER CODE BEGIN PFP */

uint8_t tx1[] = "ssss\r\n";
uint8_t buff[64];
uint8_t text_buff[300];

uint8_t mm = 0, ss = 0, ss01 = 0;

uint64_t t = 0;
uint64_t st = 0;

uint32_t t0, t1;


/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */
//void HAL_TIM_PeriodElapsedCallback(TIM_HandleTypeDef *htim)
//{
//
//	t += 1;
//}


void OLED_hx(){
	OLED_Clear();
	OLED_ShowString(6,1,(uint8_t *)"hello");
}

void run_kyber(int ntest){
	uint8_t pk[CRYPTO_PUBLICKEYBYTES];
	  uint8_t sk[CRYPTO_SECRETKEYBYTES];
	  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
	  //uint8_t key_a[1024*1024];
	  //uint8_t key_b[1024*1024];
	  uint8_t key_a[CRYPTO_BYTES];
	  uint8_t key_b[CRYPTO_BYTES];

	  uint64_t t_kp[ntest];
	  uint64_t t_enc[ntest];
	  uint64_t t_dec[ntest];


	  sprintf((char *)buff,"gen %d:%d:%d\r\n", mm,ss,ss01);
	  HAL_UART_Transmit(&huart1, buff, sizeof(buff), 10000);



	  for(int i = 0; i<ntest; i++){
		  t0 = HAL_GetTick();
		  st = t;
		  crypto_kem_keypair(pk, sk);
		  t1 = HAL_GetTick();
		  t_kp[i] = t - st;
	  }

	  sprintf((char *)buff,"%d\r\n", t_kp[0]);
	  HAL_UART_Transmit(&huart1, buff, sizeof(buff), 10000);

	  sprintf((char *)buff,"self = %u\r\n", t1-t0);
	  HAL_UART_Transmit(&huart1, buff, sizeof(buff), 10000);

//	  sprintf((char *)buff,"%u\r\n", HAL_GetTickPrio());
//	  	  HAL_UART_Transmit(&huart1, buff, sizeof(buff), 10000);


	  sprintf((char *)buff,"enc %d:%d:%d\r\n", mm,ss,ss01);
	  	  HAL_UART_Transmit(&huart1, buff, sizeof(buff), 10000);

	  for(int i = 0; i<ntest; i++){
		  t0 = HAL_GetTick();
		  st = t;
		  crypto_kem_enc(ct, key_b, pk);
		  t1 = HAL_GetTick();
		  t_enc[i] = t - st;
	  }
	  sprintf((char *)buff,"%d\r\n", t_enc[0]);
	  HAL_UART_Transmit(&huart1, buff, sizeof(buff), 10000);

	  sprintf((char *)buff,"self = %u\r\n", t1-t0);
	  HAL_UART_Transmit(&huart1, buff, sizeof(buff), 10000);

//	  for(int i = 0; i<ntest; i++){
//		  crypto_kem_enc(ct, key_b, pk);
//	    }


	  sprintf((char *)buff,"dec %d:%d:%d\r\n", mm,ss,ss01);
	  HAL_UART_Transmit(&huart1, buff, sizeof(buff), 10000);



		  for(int i = 0; i<ntest; i++){
			  t0 = HAL_GetTick();
			  st = t;
			  crypto_kem_dec(key_a, ct, sk);
			  t1 = HAL_GetTick();
			  t_dec[i] = t - st;
		  }

		  sprintf((char *)buff,"%d\r\n", t_dec[0]);
		  HAL_UART_Transmit(&huart1, buff, sizeof(buff), 10000);

		  sprintf((char *)buff,"self = %u\r\n", t1-t0);
		  HAL_UART_Transmit(&huart1, buff, sizeof(buff), 10000);

//	  for(int i = 0; i<ntest; i++){
//		  crypto_kem_dec(key_a, ct, sk);
//	    }

	    sprintf((char *)buff,"4 %d:%d:%d\r\n", mm,ss,ss01);
	    HAL_UART_Transmit(&huart1, buff, sizeof(buff), 10000);
}

void run_rsa(int ntest){

	cmox_rsa_retval_t retval;
	  size_t computed_size;

//	  if (cmox_initialize(NULL) != CMOX_INIT_SUCCESS)
//	    {
//	      Error_Handler();
//	    }

//	  sprintf((char *)buff,"1 %d:%d:%d\r\n", mm,ss,ss01);
//	  HAL_UART_Transmit(&huart1, buff, sizeof(buff), 10000);


	  cmox_rsa_construct(&Rsa_Ctx, CMOX_RSA_MATH_FUNCS, CMOX_MODEXP_PUBLIC, Working_Buffer, sizeof(Working_Buffer));

	  //cmox_rsa_construct(&Rsa_Ctx, CMOX_MATH_FUNCS_SMALL, CMOX_MODEXP_PRIVATE_LOWMEM, Working_Buffer, sizeof(Working_Buffer));

//	  sprintf((char *)buff,"2 %d:%d:%d\r\n", mm,ss,ss01);
//	  HAL_UART_Transmit(&huart1, buff, sizeof(buff), 10000);

	  /* Fill in RSA key structure using the regular private key representation */
//	  retval = cmox_rsa_setKey(&Rsa_Key,                                      /* RSA key structure to fill */
//	                           Modulus, sizeof(Modulus),                      /* Key modulus */
//	                           Public_Exponent, sizeof(Public_Exponent));     /* Public key exponent */

	  /* Fill in RSA key structure using the regular private key representation */

	  retval = cmox_rsa_setKey(&Rsa_Key,                                      /* RSA key structure to fill */
	                           Modulus_3072, sizeof(Modulus_3072),                      /* Private key modulus */
	                           Private_Exponent, sizeof(Private_Exponent));   /* Private key exponent */



	  /* Verify API returned value */
	  if (retval != CMOX_RSA_SUCCESS)
	  {
		  HAL_UART_Transmit(&huart1, (uint8_t *)"hello1\n", sizeof("hello1\n"), 10000);
	  }

//	  sprintf((char *)buff,"3 %d:%d:%d\r\n", mm,ss,ss01);
//	      HAL_UART_Transmit(&huart1, buff, sizeof(buff), 10000);





//	sprintf((char *)buff,"%u\r\n", HAL_GetTick());
//	HAL_UART_Transmit(&huart1, buff, sizeof(buff), 10000);

	  sprintf((char *)buff,"%d\r\n", t);
	  HAL_UART_Transmit(&huart1, buff, sizeof(buff), 10000);



	  for(int i = 0; i < ntest; i++){
		  t0 = HAL_GetTick();
		  sprintf((char *)buff,"%d: %u\r\n", i, t0);
		  HAL_UART_Transmit(&huart1, buff, sizeof(buff), 10000);
		  st = t;

		  sprintf((char *)buff,"%d\r\n", t);
		  HAL_UART_Transmit(&huart1, buff, sizeof(buff), 10000);
	  /* Compute directly the clear message passing all the needed parameters */
		  retval = cmox_rsa_pkcs1v22_encrypt(&Rsa_Ctx,                                 /* RSA context */
		                                     &Rsa_Key,                                 /* RSA key to use */
		                                     Message, sizeof(Message),                 /* Message to encrypt */
		                                     CMOX_RSA_PKCS1V22_HASH_SHA1,              /* Hash method to use */
		                                     Seed, sizeof(Seed),                       /* Random seed */
		                                     NULL, 0,                                  /* No label */
		                                     Computed_Encryption, &computed_size);  /* Data buffer to receive encrypted text */
		  t1 = HAL_GetTick();
		  sprintf((char *)buff,"%u\r\n", t - st);
		  HAL_UART_Transmit(&huart1, buff, sizeof(buff), 10000);



		  sprintf((char *)buff,"self %d: %u\r\n", i, t1-t0);
		  HAL_UART_Transmit(&huart1, buff, sizeof(buff), 10000);


	  }


//	  sprintf((char *)buff,"%u\r\n", HAL_GetTick());
//	  HAL_UART_Transmit(&huart1, buff, sizeof(buff), 10000);
	  sprintf((char *)buff,"finish enc\r\n");
	  HAL_UART_Transmit(&huart1, buff, sizeof(buff), 10000);

//	  retval = cmox_rsa_pkcs1v22_decrypt(&Rsa_Ctx,                                           /* RSA context */
//	                                     &Rsa_Key,                                           /* RSA key to use */
//	                                     Known_EncryptedText, sizeof(Known_EncryptedText),   /* Encrypted message */
//	                                     CMOX_RSA_PKCS1V22_HASH_SHA1,                        /* Hash method to use */
//	                                     NULL, 0,                                            /* No label */
//	                                     Computed_Text, &computed_size);   /* Data buffer to receive clear message */

//
//	  uint8_t Computed_Encryption_compare[sizeof(Known_EncryptedText)];
//
//	  for(int i = 0; i < ntest; i++){
//	  	  /* Compute directly the clear message passing all the needed parameters */
//	  		  retval = cmox_rsa_pkcs1v22_encrypt(&Rsa_Ctx,                                 /* RSA context */
//	  		                                     &Rsa_Key,                                 /* RSA key to use */
//	  		                                     Message, sizeof(Message),                 /* Message to encrypt */
//	  		                                     CMOX_RSA_PKCS1V22_HASH_SHA1,              /* Hash method to use */
//	  		                                     Seed, sizeof(Seed),                       /* Random seed */
//	  		                                     NULL, 0,                                  /* No label */
//	  		                                     Computed_Encryption_compare, &computed_size);  /* Data buffer to receive encrypted text */
//	  	  }









//	  sprintf((char *)buff,"4 %d:%d:%d\r\n", mm,ss,ss01);
//	  	      HAL_UART_Transmit(&huart1, buff, sizeof(buff), 10000);

	  /* Verify API returned value */
	  if (retval != CMOX_RSA_SUCCESS)
	  {
		  HAL_UART_Transmit(&huart1, (uint8_t *)"hello2\n", sizeof("hello2\n"), 10000);
	  }

	  /* Verify generated data size is the expected one */
//	  if (computed_size != sizeof(Message))
//	  {
//		  sprintf((char *)buff,"cz %u %u \r\n", computed_size, sizeof(Message));
//		  HAL_UART_Transmit(&huart1, buff, sizeof(buff), 10000);
////		  sprintf((char *)text_buff,"%s\r\n", (char *)Computed_Encryption);
////		  HAL_UART_Transmit(&huart1, text_buff, sizeof(text_buff), 10000);
//		  //HAL_UART_Transmit(&huart1, Known_EncryptedText, sizeof(Known_EncryptedText), 10000);
//
//	  }

	  /* Verify generated data are the expected ones */
//	  if (memcmp(Computed_Encryption, Known_EncryptedText, computed_size) != 0)
//	  {
//		  HAL_UART_Transmit(&huart1, (uint8_t *)"hello4\n", sizeof("hello4\n"), 10000);
//	  }
//
//	  if (memcmp(Computed_Encryption, Computed_Encryption_compare, computed_size) != 0)
//	  	  {
//	  		  HAL_UART_Transmit(&huart1, (uint8_t *)"not same\n", sizeof("not same\n"), 10000);
//	  	  }


	  /* Cleanup context */
	  cmox_rsa_cleanup(&Rsa_Ctx);
}


void run_ecdsa(){
	const uint8_t Private_Key[] =
	{
	  0x7d, 0x7d, 0xc5, 0xf7, 0x1e, 0xb2, 0x9d, 0xda, 0xf8, 0x0d, 0x62, 0x14, 0x63, 0x2e, 0xea, 0xe0,
	  0x3d, 0x90, 0x58, 0xaf, 0x1f, 0xb6, 0xd2, 0x2e, 0xd8, 0x0b, 0xad, 0xb6, 0x2b, 0xc1, 0xa5, 0x34
	};
	const uint8_t Remote_Public_Key[] =
	{
	  0x70, 0x0c, 0x48, 0xf7, 0x7f, 0x56, 0x58, 0x4c, 0x5c, 0xc6, 0x32, 0xca, 0x65, 0x64, 0x0d, 0xb9,
	  0x1b, 0x6b, 0xac, 0xce, 0x3a, 0x4d, 0xf6, 0xb4, 0x2c, 0xe7, 0xcc, 0x83, 0x88, 0x33, 0xd2, 0x87,
	  0xdb, 0x71, 0xe5, 0x09, 0xe3, 0xfd, 0x9b, 0x06, 0x0d, 0xdb, 0x20, 0xba, 0x5c, 0x51, 0xdc, 0xc5,
	  0x94, 0x8d, 0x46, 0xfb, 0xf6, 0x40, 0xdf, 0xe0, 0x44, 0x17, 0x82, 0xca, 0xb8, 0x5f, 0xa4, 0xac
	};
//	const uint8_t Expected_SecretX[] =
//	{
//	  0x46, 0xfc, 0x62, 0x10, 0x64, 0x20, 0xff, 0x01, 0x2e, 0x54, 0xa4, 0x34, 0xfb, 0xdd, 0x2d, 0x25,
//	  0xcc, 0xc5, 0x85, 0x20, 0x60, 0x56, 0x1e, 0x68, 0x04, 0x0d, 0xd7, 0x77, 0x89, 0x97, 0xbd, 0x7b
//	};

	/* Computed data buffer */
	uint8_t Computed_Secret[CMOX_ECC_SECP256R1_SECRET_LEN];









	cmox_ecc_retval_t retval;
	  size_t computed_size;

//	  if (cmox_initialize(NULL) != CMOX_INIT_SUCCESS)
//	    {
//	      Error_Handler();
//	    }

	  cmox_ecc_construct(&Ecc_Ctx, CMOX_ECC256_MATH_FUNCS, Working_Buffer, sizeof(Working_Buffer));
	  sprintf((char *)buff,"1 %d:%d:%d\r\n", mm,ss,ss01);
	  	  HAL_UART_Transmit(&huart1, buff, sizeof(buff), 10000);
	    /* Compute directly the shared secret passing all the needed parameters */
	    /* Note: CMOX_ECC_CURVE_SECP256R1 refer to the default SECP256R1 definition
	     * selected in cmox_default_config.h. To use a specific definition, user can
	     * directly choose:
	     * - CMOX_ECC_SECP256R1_LOWMEM to select the low RAM usage definition (slower computing)
	     * - CMOX_ECC_SECP256R1_HIGHMEM to select the high RAM usage definition (faster computing)
	     */
	    retval = cmox_ecdh(&Ecc_Ctx,                                         /* ECC context */
	                       CMOX_ECC_CURVE_SECP256R1,                         /* SECP256R1 ECC curve selected */
	                       Private_Key, sizeof(Private_Key),                 /* Local Private key */
	                       Remote_Public_Key, sizeof(Remote_Public_Key),     /* Remote Public key */
	                       Computed_Secret, &computed_size);                 /* Data buffer to receive shared secret */

	    sprintf((char *)buff,"2 %d:%d:%d\r\n", mm,ss,ss01);
	    	  HAL_UART_Transmit(&huart1, buff, sizeof(buff), 10000);

	    /* Verify API returned value */
	    if (retval != CMOX_ECC_SUCCESS)
	    {
	    	sprintf((char *)buff,"3 %d:%d:%d\r\n", mm,ss,ss01);
	    		    	  HAL_UART_Transmit(&huart1, buff, sizeof(buff), 10000);
	    }

	    /* Verify generated data size is the expected one */
	    if (computed_size != sizeof(Computed_Secret))
	    {
	    	sprintf((char *)buff,"cz %u %u \r\n", computed_size, sizeof(Message));
	    			  HAL_UART_Transmit(&huart1, buff, sizeof(buff), 10000);
	    }



	    /* Cleanup context */
	    cmox_ecc_cleanup(&Ecc_Ctx);

	    /* No more need of cryptographic services, finalize cryptographic library */
//	    if (cmox_finalize(NULL) != CMOX_INIT_SUCCESS)
//	    {
//	      Error_Handler();
//	    }

}


#include "polarssl/config.h"

#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"
#include "polarssl/bignum.h"
#include "polarssl/x509.h"
#include "polarssl/rsa.h"

#define KEY_SIZE 1024
#define EXPONENT 65537

void run_rsa2(){
	int ret;
	    rsa_context rsa;
	    entropy_context entropy;
	    ctr_drbg_context ctr_drbg;

	    const char *pers = "rsa_genkey";

	    HAL_UART_Transmit(&huart1, (uint8_t *)"hello1\n", sizeof("hello4\n"), 10000);

	    entropy_init( &entropy );
	    if( ( ret = ctr_drbg_init( &ctr_drbg, entropy_func, &entropy,
	                               (const unsigned char *) pers,
	                               strlen( pers ) ) ) != 0 )
	    {
	    	HAL_UART_Transmit(&huart1, (uint8_t *)"hello2\n", sizeof("hello4\n"), 10000);
	    }

	    HAL_UART_Transmit(&huart1, (uint8_t *)"hello3\n", sizeof("hello4\n"), 10000);

	    rsa_init( &rsa, RSA_PKCS_V15, 0 );

	    if( ( ret = rsa_gen_key( &rsa, ctr_drbg_random, &ctr_drbg, KEY_SIZE,
	                             EXPONENT ) ) != 0 )
	    {
	    	HAL_UART_Transmit(&huart1, (uint8_t *)"hello4\n", sizeof("hello4\n"), 10000);
	    }

	    char *encst = "asdffghhj";
	    unsigned char input[1024];
	    unsigned char buf[512];

//	    if( ( ret = rsa_pkcs1_encrypt( &rsa, ctr_drbg_random, &ctr_drbg,
//	                                       RSA_PUBLIC, strlen( encst ),
//	                                       input, buf ) ) != 0 )
//	        {
//	    	HAL_UART_Transmit(&huart1, (uint8_t *)"hello4\n", sizeof("hello4\n"), 10000);
//	        }

	    HAL_UART_Transmit(&huart1, (uint8_t *)"finish\n", sizeof("finish\n"), 10000);
}


void kyber_kex(){
	uint8_t pk[CRYPTO_PUBLICKEYBYTES];
	  uint8_t sk[CRYPTO_SECRETKEYBYTES];
	  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
	  //uint8_t key_a[1024*1024];
	  //uint8_t key_b[1024*1024];
	  uint8_t key_a[CRYPTO_BYTES];
	  uint8_t key_b[CRYPTO_BYTES];
	  uint8_t buf[2*CRYPTO_BYTES];

//	  randombytes(buf, KYBER_SYMBYTES);




    sprintf((char *)buff,"self = %u\r\n", HAL_GetTick());
    HAL_UART_Transmit(&huart1, buff, sizeof(buff), 10000);

    t0 = HAL_GetTick();

  // Perform unilaterally authenticated key exchange
//  kex_uake_initA(uake_senda, tk, eska, pkb); // Run by Alice

  crypto_kem_keypair(pk, sk);

  crypto_kem_enc(ct, buf, pk);

//  sprintf((char *)buff,"self = %u\r\n", HAL_GetTick());
//  HAL_UART_Transmit(&huart1, buff, sizeof(buff), 10000);

//  kex_uake_sharedB(uake_sendb, kb, uake_senda, skb); // Run by Bob

  crypto_kem_dec(buf, ct, sk);
  crypto_kem_keypair(pk, sk);
  crypto_kem_enc(ct, buf, pk);
  kdf(buf, buf, 2*CRYPTO_BYTES);

//  kex_uake_sharedA(ka, uake_sendb, tk, eska); // Run by Alice

  crypto_kem_dec(buf, ct, sk);
  kdf(buf, buf, 2*CRYPTO_BYTES);



  t1 = HAL_GetTick();


  sprintf((char *)buff,"self = %u\r\n", t1-t0);
  HAL_UART_Transmit(&huart1, buff, sizeof(buff), 10000);
  //if(memcmp(ka,kb,KEX_SSBYTES))
  //  printf("Error in UAKE\n");

  //if(!memcmp(ka,zero,KEX_SSBYTES))
  //  printf("Error: UAKE produces zero key\n");


}


void kyber_gen(){
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
  uint8_t key_a[CRYPTO_BYTES];
  uint8_t buf[2*CRYPTO_BYTES];

  sprintf((char *)buff,"self = %u\r\n", HAL_GetTick());
  HAL_UART_Transmit(&huart1, buff, sizeof(buff), 10000);

  t0 = HAL_GetTick();
  crypto_kem_keypair(pk, sk);
  crypto_kem_enc(ct, buf, pk);
  t1 = HAL_GetTick();

  sprintf((char *)buff,"self = %u\r\n", t1-t0);
  HAL_UART_Transmit(&huart1, buff, sizeof(buff), 10000);

  t0 = HAL_GetTick();
  crypto_kem_dec(buf, ct, sk);
  crypto_kem_keypair(pk, sk);
  t1 = HAL_GetTick();

  sprintf((char *)buff,"self = %u\r\n", t1-t0);
  HAL_UART_Transmit(&huart1, buff, sizeof(buff), 10000);
}






static void pack_pk(uint8_t r[KYBER_INDCPA_PUBLICKEYBYTES],
                    polyvec *pk,
                    const uint8_t seed[KYBER_SYMBYTES])
{
  size_t i;
  polyvec_tobytes(r, pk);
  for(i=0;i<KYBER_SYMBYTES;i++)
    r[i+KYBER_POLYVECBYTES] = seed[i];
}

static void unpack_pk(polyvec *pk,
                      uint8_t seed[KYBER_SYMBYTES],
                      const uint8_t packedpk[KYBER_INDCPA_PUBLICKEYBYTES])
{
  size_t i;
  polyvec_frombytes(pk, packedpk);
  for(i=0;i<KYBER_SYMBYTES;i++)
    seed[i] = packedpk[i+KYBER_POLYVECBYTES];
}

static void pack_sk(uint8_t r[KYBER_INDCPA_SECRETKEYBYTES], polyvec *sk)
{
  polyvec_tobytes(r, sk);
}

static void unpack_sk(polyvec *sk, const uint8_t packedsk[KYBER_INDCPA_SECRETKEYBYTES])
{
  polyvec_frombytes(sk, packedsk);
}

#define gen_a(A,B)  gen_matrix(A,B,0)
#define gen_at(A,B) gen_matrix(A,B,1)


void special_test(){
	  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
	  uint8_t sk[CRYPTO_SECRETKEYBYTES];
	  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
	  uint8_t key[CRYPTO_BYTES];

	  crypto_kem_keypair(pk, sk);


	  uint8_t seed[KYBER_SYMBYTES];
	  polyvec pkpv, at[KYBER_K];

	  t0 = HAL_GetTick();
	  hash_h(ct, sk, CRYPTO_SECRETKEYBYTES);
	  t1 = HAL_GetTick();

	  sprintf((char *)buff,"self = %u\r\n", t1-t0);
	  HAL_UART_Transmit(&huart1, buff, sizeof(buff), 10000);



	  unpack_pk(&pkpv, seed, pk);
	  t0 = HAL_GetTick();
	  gen_at(at, seed);
	  t1 = HAL_GetTick();

	  sprintf((char *)buff,"self = %u\r\n", t1-t0);
	  HAL_UART_Transmit(&huart1, buff, sizeof(buff), 10000);


	  polyvec skpv;

	  t0 = HAL_GetTick();
	  unpack_sk(&skpv, sk);
	  t1 = HAL_GetTick();

	  sprintf((char *)buff,"self = %u\r\n", t1-t0);
	  HAL_UART_Transmit(&huart1, buff, sizeof(buff), 10000);

}
/* USER CODE END 0 */

/**
  * @brief  The application entry point.
  * @retval int
  */
int main(void)
{
  /* USER CODE BEGIN 1 */

  /* USER CODE END 1 */

  /* MCU Configuration--------------------------------------------------------*/

  /* Reset of all peripherals, Initializes the Flash interface and the Systick. */
  HAL_Init();

  /* USER CODE BEGIN Init */

  /* USER CODE END Init */

  /* Configure the system clock */
  SystemClock_Config();

  /* USER CODE BEGIN SysInit */

  /* USER CODE END SysInit */

  /* Initialize all configured peripherals */
  MX_GPIO_Init();
  MX_USART1_UART_Init();
  /* USER CODE BEGIN 2 */

  /* USER CODE END 2 */

  /* Infinite loop */
  /* USER CODE BEGIN WHILE */

//  HAL_TIM_Base_Start_IT(&htim3);

  OLED_Init();


  OLED_Clear();
//  sprintf((char*)buff, "%d\r\n", 1234);


//  HAL_UART_Transmit(&huart1, tx1, sizeof(tx1), 10000);
//  HAL_UART_Transmit(&huart1, buff, sizeof(buff), 10000);

//   run_rsa(1);

//  run_kyber(1);

  // run_ecdsa(1);

//   run_rsa2();

//  kyber_kex();

//  kyber_gen();

  special_test();


  sprintf((char *)buff,"end %d:%d:%d\r\n", mm,ss,ss01);
  HAL_UART_Transmit(&huart1, buff, sizeof(buff), 10000);



  while (1)
  {
    /* USER CODE END WHILE */

    /* USER CODE BEGIN 3 */
  }
  /* USER CODE END 3 */
}

/**
  * @brief System Clock Configuration
  * @retval None
  */
void SystemClock_Config(void)
{
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

  /** Initializes the RCC Oscillators according to the specified parameters
  * in the RCC_OscInitTypeDef structure.
  */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSI;
  RCC_OscInitStruct.HSIState = RCC_HSI_ON;
  RCC_OscInitStruct.HSICalibrationValue = RCC_HSICALIBRATION_DEFAULT;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSI_DIV2;
  RCC_OscInitStruct.PLL.PLLMUL = RCC_PLL_MUL16;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    Error_Handler();
  }

  /** Initializes the CPU, AHB and APB buses clocks
  */
  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                              |RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV2;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_2) != HAL_OK)
  {
    Error_Handler();
  }
}

/* USER CODE BEGIN 4 */

/* USER CODE END 4 */

/**
  * @brief  This function is executed in case of error occurrence.
  * @retval None
  */
void Error_Handler(void)
{
  /* USER CODE BEGIN Error_Handler_Debug */
  /* User can add his own implementation to report the HAL error return state */
  __disable_irq();
  while (1)
  {
  }
  /* USER CODE END Error_Handler_Debug */
}

#ifdef  USE_FULL_ASSERT
/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred.
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t *file, uint32_t line)
{
  /* USER CODE BEGIN 6 */
  /* User can add his own implementation to report the file name and line number,
     ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */
  /* USER CODE END 6 */
}
#endif /* USE_FULL_ASSERT */
