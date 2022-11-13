################################################################################
# Automatically-generated file. Do not edit!
# Toolchain: GNU Tools for STM32 (10.3-2021.10)
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../Core/Src/library/aes.c \
../Core/Src/library/arc4.c \
../Core/Src/library/asn1parse.c \
../Core/Src/library/asn1write.c \
../Core/Src/library/base64.c \
../Core/Src/library/bignum.c \
../Core/Src/library/blowfish.c \
../Core/Src/library/camellia.c \
../Core/Src/library/certs.c \
../Core/Src/library/cipher.c \
../Core/Src/library/cipher_wrap.c \
../Core/Src/library/ctr_drbg.c \
../Core/Src/library/des.c \
../Core/Src/library/dhm.c \
../Core/Src/library/entropy.c \
../Core/Src/library/entropy_poll.c \
../Core/Src/library/gcm.c \
../Core/Src/library/havege.c \
../Core/Src/library/md.c \
../Core/Src/library/md2.c \
../Core/Src/library/md4.c \
../Core/Src/library/md5.c \
../Core/Src/library/md_wrap.c \
../Core/Src/library/padlock.c \
../Core/Src/library/pbkdf2.c \
../Core/Src/library/pem.c \
../Core/Src/library/pkcs11.c \
../Core/Src/library/pkcs12.c \
../Core/Src/library/pkcs5.c \
../Core/Src/library/rsa.c \
../Core/Src/library/sha1.c \
../Core/Src/library/sha2.c \
../Core/Src/library/sha4.c \
../Core/Src/library/timing.c \
../Core/Src/library/version.c \
../Core/Src/library/x509write.c \
../Core/Src/library/xtea.c 

OBJS += \
./Core/Src/library/aes.o \
./Core/Src/library/arc4.o \
./Core/Src/library/asn1parse.o \
./Core/Src/library/asn1write.o \
./Core/Src/library/base64.o \
./Core/Src/library/bignum.o \
./Core/Src/library/blowfish.o \
./Core/Src/library/camellia.o \
./Core/Src/library/certs.o \
./Core/Src/library/cipher.o \
./Core/Src/library/cipher_wrap.o \
./Core/Src/library/ctr_drbg.o \
./Core/Src/library/des.o \
./Core/Src/library/dhm.o \
./Core/Src/library/entropy.o \
./Core/Src/library/entropy_poll.o \
./Core/Src/library/gcm.o \
./Core/Src/library/havege.o \
./Core/Src/library/md.o \
./Core/Src/library/md2.o \
./Core/Src/library/md4.o \
./Core/Src/library/md5.o \
./Core/Src/library/md_wrap.o \
./Core/Src/library/padlock.o \
./Core/Src/library/pbkdf2.o \
./Core/Src/library/pem.o \
./Core/Src/library/pkcs11.o \
./Core/Src/library/pkcs12.o \
./Core/Src/library/pkcs5.o \
./Core/Src/library/rsa.o \
./Core/Src/library/sha1.o \
./Core/Src/library/sha2.o \
./Core/Src/library/sha4.o \
./Core/Src/library/timing.o \
./Core/Src/library/version.o \
./Core/Src/library/x509write.o \
./Core/Src/library/xtea.o 

C_DEPS += \
./Core/Src/library/aes.d \
./Core/Src/library/arc4.d \
./Core/Src/library/asn1parse.d \
./Core/Src/library/asn1write.d \
./Core/Src/library/base64.d \
./Core/Src/library/bignum.d \
./Core/Src/library/blowfish.d \
./Core/Src/library/camellia.d \
./Core/Src/library/certs.d \
./Core/Src/library/cipher.d \
./Core/Src/library/cipher_wrap.d \
./Core/Src/library/ctr_drbg.d \
./Core/Src/library/des.d \
./Core/Src/library/dhm.d \
./Core/Src/library/entropy.d \
./Core/Src/library/entropy_poll.d \
./Core/Src/library/gcm.d \
./Core/Src/library/havege.d \
./Core/Src/library/md.d \
./Core/Src/library/md2.d \
./Core/Src/library/md4.d \
./Core/Src/library/md5.d \
./Core/Src/library/md_wrap.d \
./Core/Src/library/padlock.d \
./Core/Src/library/pbkdf2.d \
./Core/Src/library/pem.d \
./Core/Src/library/pkcs11.d \
./Core/Src/library/pkcs12.d \
./Core/Src/library/pkcs5.d \
./Core/Src/library/rsa.d \
./Core/Src/library/sha1.d \
./Core/Src/library/sha2.d \
./Core/Src/library/sha4.d \
./Core/Src/library/timing.d \
./Core/Src/library/version.d \
./Core/Src/library/x509write.d \
./Core/Src/library/xtea.d 


# Each subdirectory must supply rules for building sources it contributes
Core/Src/library/%.o Core/Src/library/%.su: ../Core/Src/library/%.c Core/Src/library/subdir.mk
	arm-none-eabi-gcc "$<" -mcpu=cortex-m3 -std=gnu11 -g3 -DDEBUG -DUSE_HAL_DRIVER -DSTM32F103xB -c -I../Core/Inc -I../Drivers/STM32F1xx_HAL_Driver/Inc/Legacy -I../Drivers/STM32F1xx_HAL_Driver/Inc -I../Drivers/CMSIS/Device/ST/STM32F1xx/Include -I../Drivers/CMSIS/Include -I"C:/Users/Administrator/Desktop/stm/STM32CubeExpansion_Crypto_V4.0.1/Middlewares/ST/STM32_Cryptographic/include" -I"C:/Users/Administrator/Desktop/stm/t2/Core/Inc/polarssl" -I"C:/Users/Administrator/Desktop/stm/t2/Core/Inc/lwip" -O0 -ffunction-sections -fdata-sections -Wall -fomit-frame-pointer -fstack-usage -MMD -MP -MF"$(@:%.o=%.d)" -MT"$@" --specs=nano.specs -mfloat-abi=soft -mthumb -o "$@"

clean: clean-Core-2f-Src-2f-library

clean-Core-2f-Src-2f-library:
	-$(RM) ./Core/Src/library/aes.d ./Core/Src/library/aes.o ./Core/Src/library/aes.su ./Core/Src/library/arc4.d ./Core/Src/library/arc4.o ./Core/Src/library/arc4.su ./Core/Src/library/asn1parse.d ./Core/Src/library/asn1parse.o ./Core/Src/library/asn1parse.su ./Core/Src/library/asn1write.d ./Core/Src/library/asn1write.o ./Core/Src/library/asn1write.su ./Core/Src/library/base64.d ./Core/Src/library/base64.o ./Core/Src/library/base64.su ./Core/Src/library/bignum.d ./Core/Src/library/bignum.o ./Core/Src/library/bignum.su ./Core/Src/library/blowfish.d ./Core/Src/library/blowfish.o ./Core/Src/library/blowfish.su ./Core/Src/library/camellia.d ./Core/Src/library/camellia.o ./Core/Src/library/camellia.su ./Core/Src/library/certs.d ./Core/Src/library/certs.o ./Core/Src/library/certs.su ./Core/Src/library/cipher.d ./Core/Src/library/cipher.o ./Core/Src/library/cipher.su ./Core/Src/library/cipher_wrap.d ./Core/Src/library/cipher_wrap.o ./Core/Src/library/cipher_wrap.su ./Core/Src/library/ctr_drbg.d ./Core/Src/library/ctr_drbg.o ./Core/Src/library/ctr_drbg.su ./Core/Src/library/des.d ./Core/Src/library/des.o ./Core/Src/library/des.su ./Core/Src/library/dhm.d ./Core/Src/library/dhm.o ./Core/Src/library/dhm.su ./Core/Src/library/entropy.d ./Core/Src/library/entropy.o ./Core/Src/library/entropy.su ./Core/Src/library/entropy_poll.d ./Core/Src/library/entropy_poll.o ./Core/Src/library/entropy_poll.su ./Core/Src/library/gcm.d ./Core/Src/library/gcm.o ./Core/Src/library/gcm.su ./Core/Src/library/havege.d ./Core/Src/library/havege.o ./Core/Src/library/havege.su ./Core/Src/library/md.d ./Core/Src/library/md.o ./Core/Src/library/md.su ./Core/Src/library/md2.d ./Core/Src/library/md2.o ./Core/Src/library/md2.su ./Core/Src/library/md4.d ./Core/Src/library/md4.o ./Core/Src/library/md4.su ./Core/Src/library/md5.d ./Core/Src/library/md5.o ./Core/Src/library/md5.su ./Core/Src/library/md_wrap.d ./Core/Src/library/md_wrap.o ./Core/Src/library/md_wrap.su ./Core/Src/library/padlock.d ./Core/Src/library/padlock.o ./Core/Src/library/padlock.su ./Core/Src/library/pbkdf2.d ./Core/Src/library/pbkdf2.o ./Core/Src/library/pbkdf2.su ./Core/Src/library/pem.d ./Core/Src/library/pem.o ./Core/Src/library/pem.su ./Core/Src/library/pkcs11.d ./Core/Src/library/pkcs11.o ./Core/Src/library/pkcs11.su ./Core/Src/library/pkcs12.d ./Core/Src/library/pkcs12.o ./Core/Src/library/pkcs12.su ./Core/Src/library/pkcs5.d ./Core/Src/library/pkcs5.o ./Core/Src/library/pkcs5.su ./Core/Src/library/rsa.d ./Core/Src/library/rsa.o ./Core/Src/library/rsa.su ./Core/Src/library/sha1.d ./Core/Src/library/sha1.o ./Core/Src/library/sha1.su ./Core/Src/library/sha2.d ./Core/Src/library/sha2.o ./Core/Src/library/sha2.su ./Core/Src/library/sha4.d ./Core/Src/library/sha4.o ./Core/Src/library/sha4.su ./Core/Src/library/timing.d ./Core/Src/library/timing.o ./Core/Src/library/timing.su ./Core/Src/library/version.d ./Core/Src/library/version.o ./Core/Src/library/version.su ./Core/Src/library/x509write.d ./Core/Src/library/x509write.o ./Core/Src/library/x509write.su ./Core/Src/library/xtea.d ./Core/Src/library/xtea.o ./Core/Src/library/xtea.su

.PHONY: clean-Core-2f-Src-2f-library

