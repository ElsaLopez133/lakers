MEMORY
{
  /* NOTE 1 K = 1 KiBi = 1024 bytes */
  FLASH : ORIGIN = 0x00000000, LENGTH = 1024K
  RAM : ORIGIN = 0x20000000, LENGTH = 256K

  /* These values correspond to the NRF52840 with Softdevices S140 7.3.0 */
  /*
     FLASH : ORIGIN = 0x00027000, LENGTH = 868K
     RAM : ORIGIN = 0x20020000, LENGTH = 128K
  */
}
/* Define stack size */
__stack_size = 0x1000; /* 4KB stack */

/* Define stack boundaries */
__stack_start__ = ORIGIN(RAM) + LENGTH(RAM);  /* End of RAM */
__stack_end__ = __stack_start__ - __stack_size; /* Subtract stack size to get start */