#pragma once

class Mutex
{
public:
    void Init();

    void Lock();
    void Unlock();

private:
    KMUTEX _mutex;
};
