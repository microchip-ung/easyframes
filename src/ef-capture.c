#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include "ef.h"


static struct capture *HEAD = 0;

int capture_cnt() {
    int i = 0;
    struct capture *p = HEAD;

    while (p) {
        i++;
        p = p->next;
    }

    return i;
}

static void capture_push(struct capture *c) {
    struct capture *p = HEAD;

    if (!HEAD) {
        HEAD = c;
        return;
    }

    while (p->next)
        p = p->next;

    p->next = c;
}

static struct capture * capture_by_pid(pid_t pid) {
    struct capture *p = HEAD;

    while (p) {
        if (p->pid == pid)
            return p;

        p = p->next;
    }

    return 0;
}


int capture_add(char *s) {
    // <if>,[<snaplen>],[<sync>],[<file>]
    const char *s_elements[5] = {};
    struct capture *c;
    buf_t *b, *b_old, *b_tmp;
    int i = 0;
    char *p;

    for (i = 0; s && i < 5; ++i) {
        s_elements[i] = s;

        if ((p = strchr(s, ','))) {
            *p = 0;
            s = p + 1;
        } else {
            s = 0;
        }
    }

    if (s_elements[0]) {
        b = bprintf("tcpdump -i %s", s_elements[0]);
    } else {
        return -1;
    }

    // snaplen
    if (s_elements[1] && *s_elements[1]) {
        b_old = b;
        b = bprintf("%s -s %s", b_old->data, s_elements[1]);
        bfree(b_old);
        b_old = 0;
        if (!b)
            return -1;
    }

    // sync
    if (s_elements[2] && *s_elements[2]) {
        b_old = b;
        b = bprintf("%s -j %s", b_old->data, s_elements[2]);
        bfree(b_old);
        b_old = 0;
        if (!b)
            return -1;
    }

    // file
    if (s_elements[3] && *s_elements[3]) {
        b_tmp = bprintf("%s", s_elements[3]);
    } else {
        b_tmp = bprintf("%s.pcap", s_elements[0]);
    }
    // pcap is not overwriting!!!
    unlink((char *)b_tmp->data);

    b_old = b;
    b = bprintf("%s -w %s", b_old->data, b_tmp->data);
    bfree(b_old);
    bfree(b_tmp);
    b_tmp = 0;
    b_old = 0;
    if (!b)
        return -1;

    // Count
    if (s_elements[4] && *s_elements[4]) {
        b_old = b;
        b = bprintf("%s -c %s", b_old->data, s_elements[4]);
        bfree(b_old);
        b_old = 0;
        if (!b)
            return -1;
    }


    //b_old = b;
    //b = bprintf("%s > /dev/null", b_old->data);
    //bfree(b_old);
    //b_old = 0;


    c = calloc(1, sizeof(*c));

    if (!c) {
        bfree(b);
        return -1;
    }

    c->tcpdump_cmd = b;
    capture_push(c);

    return 0;
}

void signal_empty(int sig) {
}

void signal_child(int sig) {
    struct capture *c;
    int status;
    pid_t p;

    while (1) {
        p = waitpid(-1, &status, WNOHANG);
        if (p <= 0)
            return;

        c = capture_by_pid(p);
        if (c) {
            if (WIFEXITED(status)) {
                int res = WEXITSTATUS(status);
                c->running = 0;
                if (c->res == 0)
                    c->success = 1;
                po("PID %d exited with code %d\n", p, res);
            } else if (WIFSIGNALED(status)) {
                int s = WTERMSIG(status);
                c->running = 0;
                po("PID %d exited with signal %d\n", p, s);
            }
        }
    }
}

static int capture_execl(const char *c) {
    int res;

    res = execl("/bin/bash", "bash", "-c", c, (char *) NULL);
    return res;
}

static int capture_start(struct capture *c) {
    int pid;
    signal(SIGCHLD, &signal_child);

    pid = fork();

    if (pid == 0) {
        return capture_execl((char *)c->tcpdump_cmd->data);
    }

    if (pid > 0) {
        c->pid = pid;
        c->running = 1;
        po("PID %d -> %s\n", c->pid, c->tcpdump_cmd->data);
    }

    return c->pid;
}

int capture_all_start() {
    struct capture *p = HEAD;

    while (p) {
        capture_start(p);
        p = p->next;
    }

    if (HEAD) {
        // We need to wait a bit before tcpdump is ready to capture frames
        // TODO, read the output from tcpdump instead
        sleep(3);
    }

    return 0;
}

static void wait_poll(int times) {
    int i;
    struct capture *p;

    for (i = 0; i < times; ++i) {
        int j = 0;

        usleep(1000);
        signal_child(0);

        // Check if we still have pending processes
        for (p = HEAD; p; p = p->next) {
            if (p->running)
                j++;
        }

        if (j == 0)
            break;
    }
}

int capture_all_stop() {
    struct capture *p;
    int cnt = 0;

    // Signal all running
    for (p = HEAD; p; p = p->next) {
        if (p->running) {
            cnt++;
        }
    }

    if (cnt) {
        // Apparently it take some time from the frame is received until it find
        // its way to pcap file.
        sleep(3);
    }

    signal(SIGCHLD, signal_empty);

    // Signal all running
    for (p = HEAD; p; p = p->next) {
        if (p->running) {
            kill(p->pid, SIGINT);
        }
    }

    wait_poll(10000);

    // If processes are still runnign, then kill them
    for (p = HEAD; p; p = p->next) {
        if (p->running) {
            po("Killing: %d!\n", p->pid);
            kill(p->pid, SIGTERM);
        }
    }

    wait_poll(10000);

    p = HEAD;
    while (p) {
        struct capture *pp = p;
        p = p->next;
        bfree(pp->tcpdump_cmd);
        free(pp);
    }

    return 0;
}

