// RUN: %check_clang_tidy %s misc-no-assign-int-to-ptr %t

#define NULL 0
#define CONST_ADDRESS 0xEC0A0000
 

// FIXME: Add something that triggers the check here.
namespace BadCases {
    //Variable declarations
    static unsigned char volatile* bad_register_CStyle = (unsigned char volatile*)(CONST_ADDRESS); 
    // CHECK-MESSAGES: :[[@LINE-1]]:58: warning: Assigning a constant address other then NULL and 0 is a bad practice. CWE-587 [misc-no-assign-int-to-ptr]

    static unsigned char volatile* bad_register_CXX = reinterpret_cast<unsigned char volatile*>(CONST_ADDRESS); 
    // CHECK-MESSAGES: :[[@LINE-1]]:55: warning: Assigning a constant address other then NULL and 0 is a bad practice. CWE-587 [misc-no-assign-int-to-ptr]

    int (*bad_CXX_funcptr)(float, char, char) = reinterpret_cast<int(*)(float,char,char)>(CONST_ADDRESS);    
    // CHECK-MESSAGES: :[[@LINE-1]]:49: warning: Assigning a constant address other then NULL and 0 is a bad practice. CWE-587 [misc-no-assign-int-to-ptr]

    int (*bad_CStyle_funcptr)() = (int(*)())CONST_ADDRESS;
    // CHECK-MESSAGES: :[[@LINE-1]]:35: warning: Assigning a constant address other then NULL and 0 is a bad practice. CWE-587 [misc-no-assign-int-to-ptr]

    //Array initialization
    int a = 10;
    int b = 4;
    int c;
    int* pa = &a;
    int* pb = &b;
    int* pc = &c;
    int* bad_cstyle_array[] = {pa, (int*)CONST_ADDRESS, pb, pc};
    // CHECK-MESSAGES: :[[@LINE-1]]:36: warning: Assigning a constant address other then NULL and 0 is a bad practice. CWE-587 [misc-no-assign-int-to-ptr]

    int* bad_cxx_array[] = {pb, pc, reinterpret_cast<int*>(CONST_ADDRESS), pa};
    // CHECK-MESSAGES: :[[@LINE-1]]:37: warning: Assigning a constant address other then NULL and 0 is a bad practice. CWE-587 [misc-no-assign-int-to-ptr]



    //Return value from functions
    volatile unsigned long* bad_getAddr_CXX() 
    {
        return reinterpret_cast<volatile unsigned long*>(CONST_ADDRESS); 
    }
    // CHECK-MESSAGES: :[[@LINE-2]]:16: warning: Assigning a constant address other then NULL and 0 is a bad practice. CWE-587 [misc-no-assign-int-to-ptr]

    volatile unsigned long* bad_getAddr_CStyle() 
    {
        return (volatile unsigned long*)CONST_ADDRESS; 
    }
    // CHECK-MESSAGES: :[[@LINE-2]]:16: warning: Assigning a constant address other then NULL and 0 is a bad practice. CWE-587 [misc-no-assign-int-to-ptr]

    //Class declaration without further specification
    template<typename T>
    class Slp
    {
        public:
        Slp()
        {
            ptr1_ = (T*)CONST_ADDRESS;
            ptr2_ = nullptr;
        }
        private:
        T* ptr1_;
        T* ptr2_;
    };
    // CHECK-MESSAGES: :[[@LINE-7]]:21: warning: Assigning a constant address other then NULL and 0 is a bad practice. CWE-587 [misc-no-assign-int-to-ptr]
    
    //Class declaration with further specification
    template<typename T>
    class Sloppy
    {
        public:
        Sloppy()
        {
            ptr1_ = (T*)CONST_ADDRESS;
            ptr2_ = nullptr;
        }    
        // CHECK-MESSAGES: :[[@LINE-3]]:21: warning: Assigning a constant address other then NULL and 0 is a bad practice. CWE-587 [misc-no-assign-int-to-ptr]

        explicit Sloppy(T* ptr)
        : ptr1_(ptr)
        , ptr2_(ptr)
        {}
        
        Sloppy(T* ptr1, T* ptr2)
        {
            ptr1_ = ptr1;
            ptr2_ = ptr2;
        }
        Sloppy(const Sloppy& other) = default;

        Sloppy& operator=(const Sloppy& rhs) = default;

        int someFunc(float* value)
        {
            *value += 2.5;
            return 0;
        }

        private:
        T* ptr1_;
        T* ptr2_;
    };

    int func()
    {
        //Initialization in constructor 
        Sloppy<float> A;
        Sloppy<float> F;

        //Passing value to constructor
        Sloppy<unsigned long> B((unsigned long*)CONST_ADDRESS, (unsigned long*)CONST_ADDRESS);
        // CHECK-MESSAGES: :[[@LINE-1]]:33: warning: Assigning a constant address other then NULL and 0 is a bad practice. CWE-587 [misc-no-assign-int-to-ptr]
        // CHECK-MESSAGES: :[[@LINE-2]]:64: warning: Assigning a constant address other then NULL and 0 is a bad practice. CWE-587 [misc-no-assign-int-to-ptr]

        Sloppy<float> C(reinterpret_cast<float*>(CONST_ADDRESS), reinterpret_cast<float*>(CONST_ADDRESS));
        // CHECK-MESSAGES: :[[@LINE-1]]:25: warning: Assigning a constant address other then NULL and 0 is a bad practice. CWE-587 [misc-no-assign-int-to-ptr]
        // CHECK-MESSAGES: :[[@LINE-2]]:66: warning: Assigning a constant address other then NULL and 0 is a bad practice. CWE-587 [misc-no-assign-int-to-ptr]

        //Declatation with initialization
        Sloppy<unsigned long> D = {Sloppy<unsigned long>((unsigned long*)CONST_ADDRESS)};
        // CHECK-MESSAGES: :[[@LINE-1]]:58: warning: Assigning a constant address other then NULL and 0 is a bad practice. CWE-587 [misc-no-assign-int-to-ptr]

        Sloppy<unsigned long> E = {Sloppy<unsigned long>(reinterpret_cast<unsigned long*>(CONST_ADDRESS))};
        // CHECK-MESSAGES: :[[@LINE-1]]:58: warning: Assigning a constant address other then NULL and 0 is a bad practice. CWE-587 [misc-no-assign-int-to-ptr]

        //Value passed to operator
        A = {Sloppy<float>((float*)CONST_ADDRESS)};    
        // CHECK-MESSAGES: :[[@LINE-1]]:28: warning: Assigning a constant address other then NULL and 0 is a bad practice. CWE-587 [misc-no-assign-int-to-ptr]

        F = {Sloppy<float>(reinterpret_cast<float*>(CONST_ADDRESS))};    
        // CHECK-MESSAGES: :[[@LINE-1]]:28: warning: Assigning a constant address other then NULL and 0 is a bad practice. CWE-587 [misc-no-assign-int-to-ptr]

        //Passing value to method
        A.someFunc((float*)CONST_ADDRESS);
        // CHECK-MESSAGES: :[[@LINE-1]]:20: warning: Assigning a constant address other then NULL and 0 is a bad practice. CWE-587 [misc-no-assign-int-to-ptr]

        A.someFunc(reinterpret_cast<float*>(CONST_ADDRESS));
        // CHECK-MESSAGES: :[[@LINE-1]]:20: warning: Assigning a constant address other then NULL and 0 is a bad practice. CWE-587 [misc-no-assign-int-to-ptr]

        //Initialization pointer to class assignment
        Sloppy<double>* sloppy_ptr = nullptr;
        sloppy_ptr = reinterpret_cast<Sloppy<double>*>(CONST_ADDRESS); 
        // CHECK-MESSAGES: :[[@LINE-1]]:22: warning: Assigning a constant address other then NULL and 0 is a bad practice. CWE-587 [misc-no-assign-int-to-ptr]

    }

    //Union declaration without specification
    template<typename T, typename K>
    union BadCast
    {
        T word;
        K* pointer;
    };
    // CHECK-MESSAGES: :[[@LINE-5]]:5: warning: This union has a pointer field. It can cause assigning constant address to pointer. CWE-587 [misc-no-assign-int-to-ptr]

    //Concrete union declaration
    union BadCastSpecialized
    {
        int    word;
        short* pointer;
    };
    // CHECK-MESSAGES: :[[@LINE-5]]:5: warning: This union has a pointer field. It can cause assigning constant address to pointer. CWE-587 [misc-no-assign-int-to-ptr]
};

// FIXME: Add something that doesn't trigger the check here.
namespace GoodCases {
    //Variable declarations
    static unsigned char volatile* bad_register_CStyle = (unsigned char volatile*)(NULL); 
    // CHECK-MESSAGES-NOT: :[[@LINE-1]]:58: warning: Assigning a constant address other then NULL and 0 is a bad practice. CWE-587 [misc-no-assign-int-to-ptr]

    static unsigned char volatile* bad_register_CXX = reinterpret_cast<unsigned char volatile*>(NULL); 
    // CHECK-MESSAGES-NOT: :[[@LINE-1]]:55: warning: Assigning a constant address other then NULL and 0 is a bad practice. CWE-587 [misc-no-assign-int-to-ptr]

    int (*bad_CXX_funcptr)(float, char, char) = reinterpret_cast<int(*)(float,char,char)>(NULL);    
    // CHECK-MESSAGES-NOT: :[[@LINE-1]]:49: warning: Assigning a constant address other then NULL and 0 is a bad practice. CWE-587 [misc-no-assign-int-to-ptr]

    int (*bad_CStyle_funcptr)() = (int(*)())NULL;
    // CHECK-MESSAGES-NOT: :[[@LINE-1]]:35: warning: Assigning a constant address other then NULL and 0 is a bad practice. CWE-587 [misc-no-assign-int-to-ptr]

    //Array initialization
    int a = 10;
    int b = 4;
    int c;
    int* pa = &a;
    int* pb = &b;
    int* pc = &c;
    int* bad_cstyle_array[] = {pa, (int*)NULL, pb, pc};
    // CHECK-MESSAGES-NOT: :[[@LINE-1]]:36: warning: Assigning a constant address other then NULL and 0 is a bad practice. CWE-587 [misc-no-assign-int-to-ptr]

    int* bad_cxx_array[] = {pb, pc, reinterpret_cast<int*>(NULL), pa};
    // CHECK-MESSAGES-NOT: :[[@LINE-1]]:37: warning: Assigning a constant address other then NULL and 0 is a bad practice. CWE-587 [misc-no-assign-int-to-ptr]



    //Return value from functions
    volatile unsigned long* bad_getAddr_CXX() 
    {
        return reinterpret_cast<volatile unsigned long*>(NULL); 
    }
    // CHECK-MESSAGES-NOT: :[[@LINE-2]]:16: warning: Assigning a constant address other then NULL and 0 is a bad practice. CWE-587 [misc-no-assign-int-to-ptr]

    volatile unsigned long* bad_getAddr_CStyle() 
    {
        return (volatile unsigned long*)NULL; 
    }
    // CHECK-MESSAGES-NOT: :[[@LINE-2]]:16: warning: Assigning a constant address other then NULL and 0 is a bad practice. CWE-587 [misc-no-assign-int-to-ptr]

    //Class declaration without further specification
    template<typename T>
    class Slp
    {
        public:
        Slp()
        {
            ptr1_ = (T*)NULL;
            ptr2_ = nullptr;
        }
        private:
        T* ptr1_;
        T* ptr2_;
    };
    // CHECK-MESSAGES-NOT: :[[@LINE-7]]:21: warning: Assigning a constant address other then NULL and 0 is a bad practice. CWE-587 [misc-no-assign-int-to-ptr]
    
    //Class declaration with further specification
    template<typename T>
    class Sloppy
    {
        public:
        Sloppy()
        {
            ptr1_ = (T*)NULL;
            ptr2_ = nullptr;
        }    
        // CHECK-MESSAGES-NOT: :[[@LINE-3]]:21: warning: Assigning a constant address other then NULL and 0 is a bad practice. CWE-587 [misc-no-assign-int-to-ptr]

        explicit Sloppy(T* ptr)
        : ptr1_(ptr)
        , ptr2_(ptr)
        {}
        
        Sloppy(T* ptr1, T* ptr2)
        {
            ptr1_ = ptr1;
            ptr2_ = ptr2;
        }
        Sloppy(const Sloppy& other) = default;

        Sloppy& operator=(const Sloppy& rhs) = default;

        int someFunc(float* value)
        {
            *value += 2.5;
            return 0;
        }

        private:
        T* ptr1_;
        T* ptr2_;
    };

    int func()
    {
        //Initialization in constructor 
        Sloppy<float> A;
        Sloppy<float> F;

        //Passing value to constructor
        Sloppy<unsigned long> B((unsigned long*)NULL, (unsigned long*)NULL);
        // CHECK-MESSAGES-NOT: :[[@LINE-1]]:33: warning: Assigning a constant address other then NULL and 0 is a bad practice. CWE-587 [misc-no-assign-int-to-ptr]
        // CHECK-MESSAGES-NOT: :[[@LINE-2]]:64: warning: Assigning a constant address other then NULL and 0 is a bad practice. CWE-587 [misc-no-assign-int-to-ptr]

        Sloppy<float> C(reinterpret_cast<float*>(NULL), reinterpret_cast<float*>(NULL));
        // CHECK-MESSAGES-NOT: :[[@LINE-1]]:25: warning: Assigning a constant address other then NULL and 0 is a bad practice. CWE-587 [misc-no-assign-int-to-ptr]
        // CHECK-MESSAGES-NOT: :[[@LINE-2]]:66: warning: Assigning a constant address other then NULL and 0 is a bad practice. CWE-587 [misc-no-assign-int-to-ptr]

        //Declatation with initialization
        Sloppy<unsigned long> D = {Sloppy<unsigned long>((unsigned long*)NULL)};
        // CHECK-MESSAGES-NOT: :[[@LINE-1]]:58: warning: Assigning a constant address other then NULL and 0 is a bad practice. CWE-587 [misc-no-assign-int-to-ptr]

        Sloppy<unsigned long> E = {Sloppy<unsigned long>(reinterpret_cast<unsigned long*>(NULL))};
        // CHECK-MESSAGES-NOT: :[[@LINE-1]]:58: warning: Assigning a constant address other then NULL and 0 is a bad practice. CWE-587 [misc-no-assign-int-to-ptr]

        //Value passed to operator
        A = {Sloppy<float>((float*)NULL)};    
        // CHECK-MESSAGES-NOT: :[[@LINE-1]]:28: warning: Assigning a constant address other then NULL and 0 is a bad practice. CWE-587 [misc-no-assign-int-to-ptr]

        F = {Sloppy<float>(reinterpret_cast<float*>(NULL))};    
        // CHECK-MESSAGES-NOT: :[[@LINE-1]]:28: warning: Assigning a constant address other then NULL and 0 is a bad practice. CWE-587 [misc-no-assign-int-to-ptr]

        //Passing value to method
        A.someFunc((float*)NULL);
        // CHECK-MESSAGES-NOT: :[[@LINE-1]]:20: warning: Assigning a constant address other then NULL and 0 is a bad practice. CWE-587 [misc-no-assign-int-to-ptr]

        A.someFunc(reinterpret_cast<float*>(NULL));
        // CHECK-MESSAGES-NOT: :[[@LINE-1]]:20: warning: Assigning a constant address other then NULL and 0 is a bad practice. CWE-587 [misc-no-assign-int-to-ptr]

        //Initialization pointer to class assignment
        Sloppy<double>* sloppy_ptr = nullptr;
        sloppy_ptr = reinterpret_cast<Sloppy<double>*>(NULL); 
        // CHECK-MESSAGES-NOT: :[[@LINE-1]]:22: warning: Assigning a constant address other then NULL and 0 is a bad practice. CWE-587 [misc-no-assign-int-to-ptr]

    }

};


