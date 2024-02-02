misc-no-assign-int-to-ptr
=========================

Finds assigning a constant address other than `NULL` or `0` to a pointer in C/C++ code.
Assigning a constant address is a bad practice, because using a fixed address is not 
portable and this address will not be valid in all environments or platforms.
Pointer initialization include cases of variable/field declaration with initialization, assignment,
passing value to functions, initialization array of pointers.
Also detects union declarations with pointer and not-pointer fields, because it can cause assigning a constant
to pointer.

After detect vulnerability will be generated message with pointer to begining of assignment:
``warning: Assigning a constant address other then NULL and 0 is a bad practice. CWE-587 [misc-no-assign-int-to-ptr]``

Message for union declaration:
``This union has a pointer field. It can cause assigning constant address to pointer. CWE-587 [misc-no-assign-int-to-ptr]``


Examples:


    unsigned long* IncorrectPtr = reinterpret_cast<unsigned long*>(0x00000042); //bad, warning will be generated
    unsigned long* CorrectPtr1 = reinterpret_cast<unsigned long*>(0);    //correct, no warning
    unsigned long* CorrectPtr2 = reinterpret_cast<unsigned long*>(NULL); //correct, no warning
    unsigned long* CorrectPtr3 = NULL; //correct, no warning

    union Weird //bad warning will be generated - has both pointer and not-pointer types, that can cause vulnerability.
    {
        int    word;
        short* pointer;
    };
    union Correct1 //correct
    {
        int   word;
        short pointer;
    };
    union Correct2 //correct
    {
        int*   word;
        short* pointer;
    };
    
References:

* CWE Common Weakness Enumeration [CWE-587]  https://cwe.mitre.org/data/definitions/587.html

Limitations:

* About unions, the check handles only declarations. Doesn't check whether a constant was assigned and then used
  as a pointer.
