#include "mbed.h"
#include "Crypto_light/hash/SHA256.h"
#include "mbed-rtos/rtos/rtos.h"

// Photointerrupter input pins
#define I1pin D2
#define I2pin D11
#define I3pin D12

// Incremental encoder input pins
#define CHA   D7
#define CHB   D8

// Motor Drive output pins   //Mask in output byte
#define L1Lpin D4           //0x01
#define L1Hpin D5           //0x02
#define L2Lpin D3           //0x04
#define L2Hpin D6           //0x08
#define L3Lpin D9           //0x10
#define L3Hpin D10          //0x20

// max input length
#define CHAR_ARR_SIZE 18

// pwm/motor control definitions
#define MAX_PWM_PERIOD 2000
#define MAX_TORQUE 1000
#define KP 20
#define KD 20

// function-like macros for utility
#define sgn(x) ((x)/abs(x))
#define max(x,y) ((x)>=(y)?(x):(y))
#define min(x,y) ((x)>=(y)?(y):(x))

enum MSG {MSG_RESET,   MSG_HASHCOUNT, MSG_NONCE_OK, MSG_OVERFLOW, MSG_ROT_PEN,
          MSG_MAX_SPD, MSG_NEW_KEY,   MSG_INP_ERR,  MSG_TORQUE,   MSG_TEST,
      MSG_CUR_SPD, MSG_POS,       MSG_NEW_VEL,  MSG_NEW_ROTOR_POS};


// Instantiate the serial port
RawSerial pc(SERIAL_TX, SERIAL_RX);

// Status LED
DigitalOut led1(LED1);

// Photointerrupter inputs
InterruptIn I1(I1pin);
InterruptIn I2(I2pin);
InterruptIn I3(I3pin);

// motor drive outputs
PwmOut L1L(L1Lpin);
PwmOut L2L(L2Lpin);
PwmOut L3L(L3Lpin);
DigitalOut L1H(L1Hpin);
DigitalOut L2H(L2Hpin);
DigitalOut L3H(L3Hpin);

// givens from coursework handouts - motor states etc
const int8_t    drive_table[] = {0x12,0x18,0x09,0x21,0x24,0x06,0x00,0x00};
const int8_t    state_map[] = {0x07,0x05,0x03,0x04,0x01,0x00,0x02,0x07};
volatile int8_t lead = 2, // phase lead, -2 for backwards, 2 for forwards
                origin_state = 0;


// threads for serial I/O and motor control
Thread comms_out_thrd(osPriorityNormal, 1024);
Thread comms_in_thrd(osPriorityNormal, 1024);
Thread motor_ctrl_thrd(osPriorityNormal, 2048);


// IPC via Mail object; we instantiate here
typedef struct {
    char *stub;
    uint8_t code;
    int32_t data;
} message_t;

Mail<message_t, 16> msg_out_queue;

// mutex variables
Mutex new_key_mutex;
Mutex target_speed_mutex;
Mutex rotations_pending_mutex;

// instantiate a queue to buffer incoming characters
Queue<void, 8>    serial_in_queue;
// motor control global variables
volatile int32_t    motor_position = 0,
                    target_speed = 256,
                    torque = 1000;
volatile float      rotations_pending = 0;

// hash count, reset every second when printed
volatile uint16_t hashcount = 0;
// used when selecting a new hash key
volatile uint64_t new_key = 0;

// logging function & shim macro for stringifying enum
#define put_message(code, data) put_message_(#code, code, data)
void          put_message_(char *, uint8_t, int32_t);

void          comms_out_fn(void);          // serial output thread main
void          comms_in_fn(void);           // serial input thread main
void          serial_isr(void);            // serial event ISR
void          photointerrupter_isr(void);  // motor state change ISR
void          motor_ctrl_fn(void);         // motor control thread main
void          motor_ctrl_timer_isr(void);  // poke motor_ctrl at 100ms intervals
void          parse_serial_in(char *);     // interpret serial command
void          do_hashcount(void);          // print current hash count
inline int8_t read_rotor_state(void);      // get rotor position
int8_t        motor_home(void);            // establish motor origin position
void          motor_out(int8_t, uint32_t); // do motor output

int main(void)
{

    comms_out_thrd.start(&comms_out_fn);
    motor_ctrl_thrd.start(&motor_ctrl_fn);
    comms_in_thrd.start(&comms_in_fn);

    put_message(MSG_RESET, 0);

    // sync motor to home
    rotations_pending = origin_state = motor_home();

    // register ISRs
    I1.rise(&photointerrupter_isr);
    I2.rise(&photointerrupter_isr);
    I3.rise(&photointerrupter_isr);

    I1.fall(&photointerrupter_isr);
    I2.fall(&photointerrupter_isr);
    I3.fall(&photointerrupter_isr);


    // set PWM period
    L1L.period_us(MAX_PWM_PERIOD);
    L2L.period_us(MAX_PWM_PERIOD);
    L3L.period_us(MAX_PWM_PERIOD);

    // Calling the ISR once starts the motor movement
    photointerrupter_isr();

    // SHA256-related data
    SHA256 sha256;
    uint8_t sequence[] = {0x45,0x6D,0x62,0x65,0x64,0x64,0x65,0x64,
                          0x20,0x53,0x79,0x73,0x74,0x65,0x6D,0x73,
                          0x20,0x61,0x72,0x65,0x20,0x66,0x75,0x6E,
                          0x20,0x61,0x6E,0x64,0x20,0x64,0x6F,0x20,
                          0x61,0x77,0x65,0x73,0x6F,0x6D,0x65,0x20,
                          0x74,0x68,0x69,0x6E,0x67,0x73,0x21,0x20,
                          0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                          0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    uint64_t* key = (uint64_t*)((int)sequence + 48);
    uint64_t* nonce = (uint64_t*)((int)sequence + 56);
    uint8_t hash[32];

    Ticker hashcounter;
    hashcounter.attach(&do_hashcount, 1.0);

    // Poll the rotor state and set the motor outputs accordingly to spin the motor
    while (1) {
    // compute new hash
        *key = new_key;
        sha256.computeHash(hash, sequence, 64);

        if (hash[0] == 0 && hash[1] == 0)
            put_message(MSG_NONCE_OK, *nonce);

        (*nonce)++;
        hashcount++;
    }
}

void put_message_(char *str, uint8_t code, int32_t data)
{
    message_t *message = msg_out_queue.alloc();
    message->code = code;
    message->data = data;
    message->stub = str;
    msg_out_queue.put(message);
}

void comms_out_fn()
{
    while(1) {
        osEvent new_event = msg_out_queue.get();
        message_t *message = (message_t*) new_event.value.p;
        pc.printf("[%16s], data: %010d\r\n",
              message->stub,
              message->data);
        msg_out_queue.free(message);
     }
}

// serial port ISR to receive each incoming byte and place into queue
void serial_isr()
{
    uint8_t new_char = pc.getc();
    serial_in_queue.put((void*) new_char);
}

// photointerrupter ISR drives the motors
void photointerrupter_isr()
{
    static int8_t old_rotor_state = 0;
    int8_t rotor_state = read_rotor_state();

    motor_out((rotor_state-origin_state+lead+6)%6, torque); //+6 to make sure the remainder is positive

    if (rotor_state - old_rotor_state == 5)
        motor_position--;
    else if (rotor_state - old_rotor_state == -5)
        motor_position++;
    else
        motor_position += (rotor_state - old_rotor_state);

    old_rotor_state = rotor_state;
}

// motor control thread sets a timer ISR, this is the handler
void motor_ctrl_timer_isr() { motor_ctrl_thrd.signal_set(0x1); }

// motor control thread main
void motor_ctrl_fn()
{
    Ticker motor_control_ticker;
    Timer  timer;

    uint8_t count  = 0;

    int32_t cur_pos = 0,
        old_pos = 0,
        cur_speed,
        ys,
        yr;

    uint32_t cur_time = 0,
         old_time = 0,
         time_diff;

    float cur_err = 0.0f,
          old_err = 0.0f,
          err_diff;

    motor_control_ticker.attach_us(&motor_ctrl_timer_isr,100000);

    timer.start();

    while(1) {
        // wait for the 100ms boundary
        motor_ctrl_thrd.signal_wait(0x1);

        // read state & timestamp
        cur_time = timer.read();
        cur_pos  = motor_position;

        // compute speed
        time_diff = cur_time - old_time;
        cur_speed = (cur_pos - old_pos) / time_diff;

        // prep values for next time through loop
        old_time = cur_time;
        old_pos  = cur_pos;

        count = ++count % 10;
        if (!count) {
            put_message(MSG_MAX_SPD, target_speed);
        }
        // update with motor status
        /*
         * if (!count) {
         *  put_message(MSG_CUR_SPD, cur_speed);
         *  put_message(MSG_MAX_SPD, target_speed);
         *  put_message(MSG_POS, (cur_pos/6));
         *  put_message(MSG_ROT_PEN, rotations_pending);
         *  put_message(MSG_TORQUE, torque);
         * }
         */

        // compute position error
        cur_err = rotations_pending - (cur_pos/6.0f);
        err_diff = cur_err - old_err;
        old_err = cur_err;

        // compute torques
        ys = (int32_t) (20 * (target_speed - abs(cur_speed))) * sgn(cur_err);
        yr = (int32_t) ((20 * cur_err) + (40 * err_diff));

        // select minimum absolute value torque
        if (cur_speed < 0)
            torque = max(ys, yr);
        else
            torque = min(ys, yr);

        // fix torque if negative
        if (torque < 0)
            torque = -torque, // <- comma operator in action
            lead   = -2;
        else
            lead = 2;

        // cap torque
        if (torque > MAX_TORQUE)
            torque = MAX_TORQUE;

        // finally, give the motor a kick
        photointerrupter_isr();
    }
}

// parse input with sscanf()
void parse_serial_in(char *s)
{
    // shadow output variables so writes are guaranteed atomic
    uint64_t new_key_;
    int32_t torque_;
    int32_t  target_speed_;
    float rotations_pending_;

    if (sscanf(s, "R%f", &rotations_pending_)) {

        rotations_pending += rotations_pending_;
        put_message(MSG_ROT_PEN, rotations_pending);

    } else if (sscanf(s, "V%d", &target_speed_)) {

        target_speed_mutex.lock();
        if(target_speed_ == 0) target_speed_ = 0;
        target_speed = target_speed_;
        target_speed_mutex.unlock();
        put_message(MSG_NEW_VEL, target_speed);

    } else if (sscanf(s, "K%llx", &new_key_)) {

        new_key_mutex.lock();
        new_key = new_key_;
        new_key_mutex.unlock();
        put_message(MSG_NEW_KEY, new_key);

    } else if (sscanf(s, "T%u", &torque_)) {
        torque = torque_;
        photointerrupter_isr(); //Give it a kick
        // put_message(MSG_TORQUE, torque);
    } else
        put_message(MSG_INP_ERR, 0x404);
}

void comms_in_fn()
{
    // register serial interrupt handler
    pc.attach(&serial_isr);

    char char_seq[CHAR_ARR_SIZE] = "";
    uint8_t buf_pos = 0;

    while (1) {
        if (buf_pos >= CHAR_ARR_SIZE) {
            put_message(MSG_OVERFLOW, buf_pos);
            buf_pos = 0;
        } else {
            osEvent new_event = serial_in_queue.get();
            uint8_t new_char  = (uint8_t)new_event.value.p;

            if (new_char == '\r' || new_char == '\n') {
                char_seq[buf_pos] = '\0';
                buf_pos = 0;
                parse_serial_in(char_seq);
            } else
                char_seq[buf_pos++] = new_char;
        }
    }
}

// timer ISR to print/reset hash counts every second
void do_hashcount()
{
    put_message(MSG_HASHCOUNT, hashcount);
    hashcount = 0;
}


//Set a given drive state
void motor_out(int8_t driveState, uint32_t t){

    // Lookup the output byte from the drive state.
    int8_t driveOut = drive_table[driveState & 0x07];

    // Turn off first
    if (~driveOut & 0x01) L1L.pulsewidth_us(0);
    if (~driveOut & 0x02) L1H = 1;
    if (~driveOut & 0x04) L2L.pulsewidth_us(0);
    if (~driveOut & 0x08) L2H = 1;
    if (~driveOut & 0x10) L3L.pulsewidth_us(0);
    if (~driveOut & 0x20) L3H = 1;

    // Then turn on
    if (driveOut & 0x01) L1L.pulsewidth_us(t);
    if (driveOut & 0x02) L1H = 0;
    if (driveOut & 0x04) L2L.pulsewidth_us(t);
    if (driveOut & 0x08) L2H = 0;
    if (driveOut & 0x10) L3L.pulsewidth_us(t);
    if (driveOut & 0x20) L3H = 0;
}

// Convert photointerrupter inputs to a rotor state
inline int8_t read_rotor_state()
{
    return state_map[I1 + 2*I2 + 4*I3];
}

// Basic synchronisation routine
int8_t motor_home()
{
    // Put the motor in drive state 0 and wait for it to stabilise
    motor_out(0, MAX_TORQUE);
    wait(2.0);

    // Get the rotor state
    return read_rotor_state();
}
