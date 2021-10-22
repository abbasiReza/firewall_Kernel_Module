#include<stdio.h>
#include<stdlib.h>
#include<errno.h>
#include<fcntl.h>
#include<string.h>
#include<unistd.h>
int main(){

int fd;
fd = open("/dev/firewall", O_RDWR);
if (fd < 0){
  printf("FFFFFFFFFFFFFFFFFF");
   perror("Failed to open the device...");
   return errno;

}


FILE *file = fopen ( "config.txt", "r" );
if ( file != NULL )
{
  char line [ 128 ];
  while ( fgets ( line, sizeof line, file ) != NULL )
  {

    write(fd,line,strlen(line));
  }
  fclose ( file );

}



}
