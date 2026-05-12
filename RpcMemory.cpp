#include <cstdlib>
#include <rpc.h>

extern "C"
{
    void* __RPC_USER midl_user_allocate(size_t size)
    {
        return std::malloc(size);
    }

    void __RPC_USER midl_user_free(void* pointer)
    {
        std::free(pointer);
    }
}
