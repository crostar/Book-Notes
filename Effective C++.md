# Effective C++



###  Accustoming youself to C++

#### Item 1. See C++ as a Federal

- View c++ as a federal of four sub languages: C, C with classes, template, STL
- Each sub languages has its own regulation

#### Item 2. Prefer `consts`, `enums`, and `inlines` to `#defines`

- Use `const` instead of `#defines`

  ```C++
  #define a 5 
  // becomes
  const int a = 5;
  ```

- Use `static const` on class member when needed

  ```c++
  // GamePlayer.h
  class GamePlayer {
      private:
      static const int NumTurns = 5;
      int scores[NumTurns];
      ...
  }
  
  // GamePlayer.cpp
  const int GamePlayer::NumTurns;
  ```

  Usually we can omit the definition, except when we need the address of the const member or the compiler insists us to provide a definition

- `Enum hack`

  ```c++
  class GamePlayer {
      private:
      enum { NumTurns = 5 };
      int scores[NumTurns];
      ...
  }
  ```

  `Enum` behaves more like `#defines` but not `const`, for example, you cannot get address to it.

- Use `(template) inline function`  instead of `#defines macro`



#### Item 3. Use `const` whenever possible

- `const Widget* pw` : the object that `pw` points to is unchangable, in contrast, `Widget * const pw` means `pw` pointer itself cannot be changed
- In `STL`, `const iterator` means the iterator itself cannot be changed. If we want the object to be unchangable, use `const_iterator` provided by `STL`
- `const method`: the method that can be called on `const` object, do not change the object
  - bitwise const: the requirement of compiler, meaning every bit of object should not be modified by a const method
  - logical const: a const method could modify the object, only when the client could not notice. The keyword `mutable` could get rid of the restriction of bitwise const thus implement logical const



#### Item 4. Make sure that object is initialized before it's used

- Always initialize all member objects manually since C++ do not guarantee to initialize them

- Always use member initialization list when possible

- Use local static function instead of non-local static object

  ```C++
  // FileSystem.cpp
  static FileSystem fls;
  // Directory.cpp
  Directory::Directory( params ) {
      std::size_t disks = tfs.numDisks();
      // ...
  }
  // Directory may be initialized before fls initialized, which will cause problem
  
  // Should be like this
  // FileSystem.cpp
  FileSystem& fls() {
      static FileSystem fls;
      return fls;
  }
  // Directory.cpp
  Directory::Directory( params ) {
      std::size_t disks = tfs().numDisks();
      // ...
  } 
  ```



### Constructors, Destructors, and Assignment Operators

#### Item 5. Know what functions C++ silently writes and calls

- The compiler could provide a default constructor, destructor, copy constructor and copy assignment, when you do not write them yourself.
  - All the methods that compiler provides are `public inline`
  - The complier will create those methods only if they are used somewhere
  - When the class contains members of reference or const, or it is derived from some base class that has a private copy assignment operator, the compiler will refuse to generate default copy assignment operator.



#### Item 6. Explicitly disallow the use of compiler-generated function you do not want

- Sometimes we don't want some functions, for example, an uncopyable class should not have copy constructor and copy assignment operator

- To prevent the compiler automatically generating those for us, we could declare copy constructor and copy assignment operator to private, and do not give definition.

- Another method is to declare an `uncopyable` base class and derive from it

  ```C++
  class UnCopyable {
      public:
      UnCopyable() {}
      ~unCopyable() {}
      private:
      UnCopyable(const UnCopyable&);
      UnCopyable& operator=(const UnCopyable&);
  };
  ```



#### Item 7. Declare destructors virtual in polymorphic base classes

- If a base class is designed to "deal with derived class object through base class pointer", then the destructor should be declared virtual
- Sometimes when we want to have an abstract base class, but do not have a pure virtual function on hand, we can declare the destructor as pure virtual.
  - Remember give the pure virtual destructor an empty definition to stop the complaint from compiler.



#### Item 8. Prevent exceptions leaving destructors

- It is dangerous to leave the exception in destructors unhandled, since they are always called implicitly so that the client is not able to handle the exception. 
- Deal with exceptions in the destructor, we can either
  - abort the program
  - swallow the exception
- Another way is to give the client a chance to deal with the exception, i.e. transfer the operation that may throw exceptions to a normal method instead of destructors.



#### Item 9. Never call virtual function inside constructors or destructors

- When calling constructors of derived class, the constructor of the base class is first called, in which time the extra members of derived class in uninitialized.

- Thus, if a virtual function is called here in the constructor of the base class, it is the base class version function that get called, to avoid using uninitialized members. This is not what we want.

- An alternative is to use a non-virtual function with some parameters, and let the derived class constructor pass the parameters to the base class constructor

  ```c++
  class Transaction {
      public:
      Transaction(const std::string& param) {
          //...
          logTransaction(param);
      }
      void logTransaction(const std::string& param);
  };
  
  class BuyTransaction : public Transaction {
      public:
      BuyTransaction( parameters ) : Transaction(createLogParam(parameters));
      private：
      static std::string createLogParam(parameters);
  }
  ```



#### Item 10. Have assignment operators return a reference to `*this`

- As the title says, always return a reference to `*this` in assignment operators to implement the property of continuous assignment.



#### Item 11. Handle self-assignment in the copy assignment operator

- Self-assignment may cause problems, consider the following code:

  ```C++
  Widget& Widget::operator=(const Widget& rhs) {
      delete pb;
      pb = new Bitmap(*rhs.ph);
      return *this;
  }
  ```

  Self-assignment will call copy constructor on a deleted resource, which is dangerous.

- Usually there are three ways to handle self-assignment:

  - identity test:

    ```C++
    Widget& Widget::operator=(const Widget& rhs) {
     	if (this == &rhs) return *this;
        
        delete pb;
        pb = new Bitmap(*rhs.ph);
        return *this;
    }
    ```

  - Make a copy of original pointer:

    ```c++
    Widget& Widget::operator=(const Widget& rhs) {
     	Bitmap* pOrig = pb;
        pb = new Bitmap(*rhs.ph);
        delete pOrig;
        return *this;
    }
    ```

  - Copy and Swap

    ```c++
    Widget& Widget::operator=(const Widget& rhs) {
     	Widget temp(rhs);
        swap(temp);
        return *this;
    }
    ```

    

#### Item 12. Copy all components in copying methods

- In copy constructor and copy assignment operator, make sure you
  - copy all the local members
  - call copying methods of all base classes
- If there are similar codes in copy constructor and copy assignment operator, consider make a private method `init` and let both call it.



### Resource Management

#### Item 13. Use objects to manage resources

- Resources: heap allocated memory, file resource, mutex, socket, etc.

- Two key ideas in "use objects to manage resources"

  - Resource Acquisition is Initialization (RAII): Whenever we obtain a resource, use it to initialize or assign to some resource management object
  - Release resource in the destructor.

  ```c++
  void f() {
  	std::auto_ptr<Investment> pInv(createInvestment()); // when obtaining the heap memory, use it to initialize an std::auto_ptr object
  	// ...    
  } // when leaving, the destructor of std::auto_ptr will delete the heap memory
  ```



#### Item 14. Think carefully about copying behavior in resource-managing class

- It is tricky to define copying methods in RAII class, since the behavior of copying diverges
  - Forbid copy: As item6 shows, declare copying function as private or inherit from `Uncopyable` base class
  - Reference-count: When we want to keep the resource until its last user is deleted, increment the reference count when copying. (Shallow copy)
  - Copy resource as well: Sometimes we allow there exists multiple copies of a resource, in this case we can copy both the RAII object as well as the resource. (Deep copy)
  - Transfer the ownership: Rarely we may hope that there is always one RAII object pointing to a raw resource, and the ownership is transfer from the old object to the new one.



#### Item 15. 

