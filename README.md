# Drogon JWT Filter example
A simple project to serve as an example of how to implement an JWT filter on [Drogon framework](https://github.com/an-tao/drogon).
___

## Endpoints
* Get auth token
    * Method: POST
    * Link: http://localhost/api/v1/auth/login
    * Body: ```{ "email": "0rangeFox@domain.pt", "password": "0rangeFoxIsCool", "remember": true }```
* Verify auth token
    * Method: GET
    * Link: http://localhost/api/v1/auth/verify
    * Authorization Header: ```Bearer <Token>```
___
## How to build the project
### Requirements:
Everything you need to setup this example is [here](https://github.com/an-tao/drogon/wiki/ENG-02-Installation#System-Requirements)! Just follow what is written there and then you can come back here.

### Build:
```bash
git clone https://github.com/0rangeFox/Drogon-JWT-Filter-example.git
cd Drogon-JWT-Filter-example
git submodule update --init
cd libraries/drogon/
git submodule update --init
cd ../../
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make && sudo make install
```

### Execute:
Make an copy of _config.json_ inside to build folder, and make your necessary changes and start the program.

## Frequently Asked Questions (FAQ)
* **Q**: When I try to compile this project give me error on CMakeLists telling OpenSSL wasn't found but I have it installed:
* **A**: The solution is [here](https://github.com/drogonframework/drogon/issues/1161#issuecomment-1019180325).