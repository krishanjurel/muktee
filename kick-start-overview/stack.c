#include <stdio.h> /* standard library */
#include <malloc.h> /* memory operation */



/* define a linked list structure of integer member */

struct _list
{
    int a;
    struct _list *next;
};


/* define a global variable head */
struct _list *head = NULL; /* at the start head always points to null, since no elemnts */


/*
    function push: inserts an element into the stack at the top.

    this function, inserts the elements at the top and update the 
    head pointer to point to the current element.

    value: the integer value to push

    return 0: on success, else
           -1
*/
static int push (int value)
{
    /* define a new stack item */
    struct _list *item = (struct _list *)malloc(sizeof(struct _list));
    /* check whether memory is allocated or not */
    if(item == NULL)
    {
        /* if memory allocation fails, return from here */
        return -1;
    }
    /* set the a to the value that we want to store in the stack */
    item->a=value;
    /* the current item points to the previous head */
    /* and new item becomes the new head */
    item->next = head;
    head = item;
    return 0;
}


/*
    function pop: read the top most element of the stack.
    this function returns the top element, and sets the head to the 
    next in the stack.
  

    returns:
            pointer to the current head, else
            null
*/
static struct _list *pop()
{
    /* if stack is empty, i.e head is null */
    if(head == NULL)
    {
        /* if memory allocation fails, return from here */
        return NULL;
    }

    /* now our head will point to the next element*/
    struct _list *item = head;
    /* point head to the next */
    head = head->next;
    return item;
}


int main()
{
    /* lets insert 10 elements and read them back */
    int value;
    int ret = 0;
    int count = 0;

    /* lets read 5 elements */
    for (count = 0; count < 5; count++)
    {
        printf("enter item number %d\n", count+1);

        scanf_s("%d", &value);

        /* push the item in the stack */
        ret = push(value);
        /* check for error status */
        if(ret == -1)
        {
            /* if error has occured, print a message and exit the loop */
            printf("stack push has failed, please check the program\n");
            break;
        }
    }

    /* now read the stack entries */
    /* since pop returns the pointer to the current top of the stack, lets define a 
       pointer of our stack data structure type and keep reading until it points to null
    */

    struct _list *stackHead;

    /* read the first element */
    stackHead = pop();
    /* we can loop until pop returns null */
    while(stackHead != NULL)
    {
        /* print the read value */
        printf("read item is %d\n", stackHead->a);
        /* also dont forget to release the memory allocated during push operation*/
        free(stackHead);
        /* read next */        
        stackHead = pop();
    }
    return 0;
}



















