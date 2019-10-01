#include <unistd.h>
#include <string.h>

void fun(){
    char buffer[0x20];
    read(0,buffer,0x200);
}

int main(){
    fun();
    return 0;
}
