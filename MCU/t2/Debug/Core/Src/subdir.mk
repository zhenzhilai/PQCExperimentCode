################################################################################
# Automatically-generated file. Do not edit!
# Toolchain: GNU Tools for STM32 (10.3-2021.10)
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../Core/Src/XMF_OLED_STM32Cube.c \
../Core/Src/aes256ctr.c \
../Core/Src/cbd.c \
../Core/Src/fips202.c \
../Core/Src/gpio.c \
../Core/Src/indcpa.c \
../Core/Src/kem.c \
../Core/Src/kex.c \
../Core/Src/main.c \
../Core/Src/ntt.c \
../Core/Src/poly.c \
../Core/Src/polyvec.c \
../Core/Src/randombytes.c \
../Core/Src/reduce.c \
../Core/Src/sha256.c \
../Core/Src/sha512.c \
../Core/Src/stm32f1xx_hal_msp.c \
../Core/Src/stm32f1xx_it.c \
../Core/Src/symmetric-aes.c \
../Core/Src/symmetric-shake.c \
../Core/Src/syscalls.c \
../Core/Src/sysmem.c \
../Core/Src/system_stm32f1xx.c \
../Core/Src/usart.c \
../Core/Src/verify.c 

OBJS += \
./Core/Src/XMF_OLED_STM32Cube.o \
./Core/Src/aes256ctr.o \
./Core/Src/cbd.o \
./Core/Src/fips202.o \
./Core/Src/gpio.o \
./Core/Src/indcpa.o \
./Core/Src/kem.o \
./Core/Src/kex.o \
./Core/Src/main.o \
./Core/Src/ntt.o \
./Core/Src/poly.o \
./Core/Src/polyvec.o \
./Core/Src/randombytes.o \
./Core/Src/reduce.o \
./Core/Src/sha256.o \
./Core/Src/sha512.o \
./Core/Src/stm32f1xx_hal_msp.o \
./Core/Src/stm32f1xx_it.o \
./Core/Src/symmetric-aes.o \
./Core/Src/symmetric-shake.o \
./Core/Src/syscalls.o \
./Core/Src/sysmem.o \
./Core/Src/system_stm32f1xx.o \
./Core/Src/usart.o \
./Core/Src/verify.o 

C_DEPS += \
./Core/Src/XMF_OLED_STM32Cube.d \
./Core/Src/aes256ctr.d \
./Core/Src/cbd.d \
./Core/Src/fips202.d \
./Core/Src/gpio.d \
./Core/Src/indcpa.d \
./Core/Src/kem.d \
./Core/Src/kex.d \
./Core/Src/main.d \
./Core/Src/ntt.d \
./Core/Src/poly.d \
./Core/Src/polyvec.d \
./Core/Src/randombytes.d \
./Core/Src/reduce.d \
./Core/Src/sha256.d \
./Core/Src/sha512.d \
./Core/Src/stm32f1xx_hal_msp.d \
./Core/Src/stm32f1xx_it.d \
./Core/Src/symmetric-aes.d \
./Core/Src/symmetric-shake.d \
./Core/Src/syscalls.d \
./Core/Src/sysmem.d \
./Core/Src/system_stm32f1xx.d \
./Core/Src/usart.d \
./Core/Src/verify.d 


# Each subdirectory must supply rules for building sources it contributes
Core/Src/%.o Core/Src/%.su: ../Core/Src/%.c Core/Src/subdir.mk
	arm-none-eabi-gcc "$<" -mcpu=cortex-m3 -std=gnu11 -g3 -DDEBUG -DUSE_HAL_DRIVER -DSTM32F103xB -c -I../Core/Inc -I../Drivers/STM32F1xx_HAL_Driver/Inc/Legacy -I../Drivers/STM32F1xx_HAL_Driver/Inc -I../Drivers/CMSIS/Device/ST/STM32F1xx/Include -I../Drivers/CMSIS/Include -I"C:/Users/Administrator/Desktop/stm/STM32CubeExpansion_Crypto_V4.0.1/Middlewares/ST/STM32_Cryptographic/include" -I"C:/Users/Administrator/Desktop/stm/t2/Core/Inc/polarssl" -I"C:/Users/Administrator/Desktop/stm/t2/Core/Inc/lwip" -O0 -ffunction-sections -fdata-sections -Wall -fomit-frame-pointer -fstack-usage -MMD -MP -MF"$(@:%.o=%.d)" -MT"$@" --specs=nano.specs -mfloat-abi=soft -mthumb -o "$@"

clean: clean-Core-2f-Src

clean-Core-2f-Src:
	-$(RM) ./Core/Src/XMF_OLED_STM32Cube.d ./Core/Src/XMF_OLED_STM32Cube.o ./Core/Src/XMF_OLED_STM32Cube.su ./Core/Src/aes256ctr.d ./Core/Src/aes256ctr.o ./Core/Src/aes256ctr.su ./Core/Src/cbd.d ./Core/Src/cbd.o ./Core/Src/cbd.su ./Core/Src/fips202.d ./Core/Src/fips202.o ./Core/Src/fips202.su ./Core/Src/gpio.d ./Core/Src/gpio.o ./Core/Src/gpio.su ./Core/Src/indcpa.d ./Core/Src/indcpa.o ./Core/Src/indcpa.su ./Core/Src/kem.d ./Core/Src/kem.o ./Core/Src/kem.su ./Core/Src/kex.d ./Core/Src/kex.o ./Core/Src/kex.su ./Core/Src/main.d ./Core/Src/main.o ./Core/Src/main.su ./Core/Src/ntt.d ./Core/Src/ntt.o ./Core/Src/ntt.su ./Core/Src/poly.d ./Core/Src/poly.o ./Core/Src/poly.su ./Core/Src/polyvec.d ./Core/Src/polyvec.o ./Core/Src/polyvec.su ./Core/Src/randombytes.d ./Core/Src/randombytes.o ./Core/Src/randombytes.su ./Core/Src/reduce.d ./Core/Src/reduce.o ./Core/Src/reduce.su ./Core/Src/sha256.d ./Core/Src/sha256.o ./Core/Src/sha256.su ./Core/Src/sha512.d ./Core/Src/sha512.o ./Core/Src/sha512.su ./Core/Src/stm32f1xx_hal_msp.d ./Core/Src/stm32f1xx_hal_msp.o ./Core/Src/stm32f1xx_hal_msp.su ./Core/Src/stm32f1xx_it.d ./Core/Src/stm32f1xx_it.o ./Core/Src/stm32f1xx_it.su ./Core/Src/symmetric-aes.d ./Core/Src/symmetric-aes.o ./Core/Src/symmetric-aes.su ./Core/Src/symmetric-shake.d ./Core/Src/symmetric-shake.o ./Core/Src/symmetric-shake.su ./Core/Src/syscalls.d ./Core/Src/syscalls.o ./Core/Src/syscalls.su ./Core/Src/sysmem.d ./Core/Src/sysmem.o ./Core/Src/sysmem.su ./Core/Src/system_stm32f1xx.d ./Core/Src/system_stm32f1xx.o ./Core/Src/system_stm32f1xx.su ./Core/Src/usart.d ./Core/Src/usart.o ./Core/Src/usart.su ./Core/Src/verify.d ./Core/Src/verify.o ./Core/Src/verify.su

.PHONY: clean-Core-2f-Src

