#ifndef BUZZER_COMPILER_H
#define BUZZER_COMPILER_H

#ifndef __packed
#define __packed __attribute__((packed)) 
#endif

#ifndef __init
#define __init __attribute__((constructor))
#endif



#endif