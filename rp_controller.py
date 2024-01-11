#!/usr/bin/env python
import scapy.all as scapy
import socket
import paramiko
import sys
import tkinter as tk
from tkinter import font
import tkinter.messagebox as msgbox
from tkinter import ttk
from threading import Thread
import logging
from queue import Queue
import time
from pysnmp.hlapi import *
#import pkg_resources.py2_warn

# logging setting,10=DEBUG,20=INFO
output_logging = 20


class gui_app(tk.Tk):
    scan_ip_list = []
    scan_network = "192.168.1.0/24"
    command_input = ""
    command_output = ""
    scan_proc_state = []
    ping_thread_list = []
    snmp_thread_list = []
    scan_task = []
    pass_gif = ''
    fail_gif = ''
    row_total = 32
    currentValue = 0

    label_text = ["ID", "MAC Addr", "IP Addr", "Online", "Internet", "TX (Mbps)", "RX (Mbps)",
                  "Reboot", "Start", "Stop", "Restart X"]
    ip_list = []

    def __init__(self, top=None):
        super().__init__()

        self.mac_list = ["dc:a6:32:92:ed:a8", "dc:a6:32:92:ec:8e",
                         "dc:a6:32:92:ed:bc", "dc:a6:32:92:e7:b0",
                         "dc:a6:32:92:eb:d1", "dc:a6:32:92:ec:7f",
                         "dc:a6:32:92:ed:0b", "dc:a6:32:92:ee:35",
                         "dc:a6:32:92:ec:40", "dc:a6:32:92:ed:36",
                         "dc:a6:32:92:ec:62", "dc:a6:32:92:ec:16",
                         "dc:a6:32:92:ed:f3", "dc:a6:32:92:d1:64",
                         "dc:a6:32:92:eb:c2", "dc:a6:32:92:ec:94",
                         "dc:a6:32:92:ed:c3", "dc:a6:32:92:ee:14",
                         "dc:a6:32:92:db:f0", "dc:a6:32:92:ed:75",
                         "dc:a6:32:92:ee:08", "dc:a6:32:92:eb:d7",
                         "dc:a6:32:92:eb:b3", "dc:a6:32:92:d4:61",
                         "dc:a6:32:92:e7:77", "dc:a6:32:92:ed:48",
                         "dc:a6:32:92:ee:50", "dc:a6:32:92:ed:10",
                         "dc:a6:32:92:ec:a6", "dc:a6:32:92:ee:1f",
                         "dc:a6:32:92:ed:8a", "dc:a6:32:92:ec:85"]

        self.start_logging()
        logging.info('Start init control panel')

        self.geometry("780x750+100+25")
        self.title("RP4 Controller v1.121 (2022/01/07)")

        self.pass_gif = tk.PhotoImage(file="pass.gif")
        self.fail_gif = tk.PhotoImage(file="fail.gif")

        default_font = font.nametofont("TkDefaultFont")
        default_font.configure(size=7)
        self.option_add("*Font", default_font)

        self.mac_table = self.csv_read("mac_list.txt")

        self.canvas = tk.Canvas(top, width=770, height=730, scrollregion=(0, 0, 980, 950))  # 創建canvas
        self.canvas.place(x=0, y=0)  # 放置canvas的位置
        self.MainFrame = tk.Frame(self.canvas)
        self.MainFrame.place(relx=0, rely=0, relheight=1, relwidth=1)
        #self.MainFrame.configure(relief='groove')
        #self.MainFrame.configure(borderwidth="1")
        self.vbar = tk.Scrollbar(top, orient=tk.VERTICAL, command=self.canvas.yview)  # 豎直滾動條
        self.vbar.pack(side=tk.RIGHT, fill='y')
        self.canvas.config(yscrollcommand=self.vbar.set)  # 設置
        self.canvas.create_window((0, 0), window=self.MainFrame, anchor='nw')  # create_window
        self.canvas.config(scrollregion=self.canvas.bbox("all"))
        self.MainFrame.bind('<Configure>', self.on_configure)
        self.MainFrame.bind("<MouseWheel>", self.on_mousewheel)

        self.update()

        self.title = []

        self.label_range = tk.Label(self.MainFrame, text="Network:")
        self.label_range.grid(row=0, column=0, padx=6)
        self.entry_range = tk.Entry(self.MainFrame, width=15)
        self.entry_range.grid(row=0, column=1, padx=6)
        self.entry_range.insert(tk.END, "192.168.1.0/24")

        self.btn_scan = tk.Button(self.MainFrame, text="Re-Scan", command=self.check_cpe_status)
        self.btn_scan.grid(row=0, column=2, padx=6)

        self.btn_internet = tk.Button(self.MainFrame, text="Get Internet", command=self.check_internet_status)
        self.btn_internet.grid(row=0, column=4, padx=6)

        self.btn_snmp = tk.Button(self.MainFrame, text="Get Traffic", command=self.check_traffic_status)
        self.btn_snmp.grid(row=0, column=5, padx=6)

        self.btn_reboot_all = tk.Button(self.MainFrame, text="Reboot All", command=lambda entry_id="all": self.action_reboot(entry_id))
        self.btn_reboot_all.grid(row=0, column=7, padx=6)

        self.btn_start_all = tk.Button(self.MainFrame, text="Start All", command=lambda entry_id="all": self.action_start(entry_id))
        self.btn_start_all.grid(row=0, column=8, padx=6)

        self.btn_stop_all = tk.Button(self.MainFrame, text="Stop All", command=lambda entry_id="all": self.action_stop(entry_id))
        self.btn_stop_all.grid(row=0, column=9, padx=6)

        self.btn_restart_x_all = tk.Button(self.MainFrame, text="Restart All", command=lambda entry_id="all": self.action_restart_xwindow(entry_id))
        self.btn_restart_x_all.grid(row=0, column=10, padx=6)

        self.label_timeout = tk.Label(self.MainFrame, text="Timeout(ms):")
        self.label_timeout.grid(row=1, column=0, padx=6)
        self.entry_timeout = tk.Entry(self.MainFrame, width=5)
        self.entry_timeout.grid(row=1, column=1, padx=6)
        self.entry_timeout.insert(tk.END, "400")
        self.timeout = int(self.entry_timeout.get())

        self.label_count = tk.Label(self.MainFrame, text="Retry(1~10):")
        self.label_count.grid(row=1, column=2, padx=6)
        self.entry_count = tk.Entry(self.MainFrame, width=5)
        self.entry_count.grid(row=1, column=3, padx=6)
        self.entry_count.insert(tk.END, "3")
        self.count = int(self.entry_count.get())

        for x in range(0, 11):
            self.title.append(tk.Label(self.MainFrame, text=self.label_text[x]))
            self.title[x].grid(row=2, column=x, padx=6)

        # self.btn_all = []
        # for x in range(0,4):
        #    self.btn_all.append(tk.Button(self.MainFrame, text="All"))
        #    self.btn_all[x].grid(row=1,column=x+7,padx=6)

        self.rp4_table = []
        column = 0
        for y in range(0, self.row_total):
            #if y > 15:
            #    column = 11
            #    row = y - 14
            #else:
            column = 0
            row = y + 3
            self.rp4_entry = {}
            self.rp4_entry['ID'] = tk.Label(self.MainFrame, text="ID-" + str(y + 1))
            self.rp4_entry['ID'].grid(row=row, column=0 + column, padx=1, pady=0)
            self.rp4_entry['MAC'] = tk.Entry(self.MainFrame, width=15)
            self.rp4_entry['MAC'].grid(row=row, column=1 + column, padx=1, pady=0)
            self.rp4_entry['MAC'].insert(tk.END, self.mac_table[y])
            self.rp4_entry['IP'] = tk.Entry(self.MainFrame, width=15)
            self.rp4_entry['IP'].grid(row=row, column=2 + column, padx=2, pady=0)
            self.rp4_entry['Online'] = tk.Label(self.MainFrame, text="N/A", image=self.fail_gif)
            self.rp4_entry['Online'].image = self.fail_gif
            self.rp4_entry['Online'].grid(row=row, column=3 + column, padx=2, pady=0)
            self.rp4_entry['Internet'] = tk.Label(self.MainFrame, text="N/A", image=self.fail_gif)
            self.rp4_entry['Internet'].image = self.fail_gif
            self.rp4_entry['Internet'].grid(row=row, column=4 + column, padx=2, pady=0)
            self.rp4_entry['wlan0_TX'] = tk.Entry(self.MainFrame, width=10)
            self.rp4_entry['wlan0_TX'].grid(row=row, column=5 + column, padx=2, pady=0)
            self.rp4_entry['wlan0_RX'] = tk.Entry(self.MainFrame, width=10)
            self.rp4_entry['wlan0_RX'].grid(row=row, column=6 + column, padx=2, pady=0)
            self.rp4_entry['Reboot'] = tk.Button(self.MainFrame, text="Reboot",
                                                 command=lambda entry_id=y: self.action_reboot(entry_id))
            self.rp4_entry['Reboot'].grid(row=row, column=7 + column, padx=2, pady=0)
            self.rp4_entry['Start'] = tk.Button(self.MainFrame, text="Start",
                                                command=lambda entry_id=y: self.action_start(entry_id))
            self.rp4_entry['Start'].grid(row=row, column=8 + column, padx=2, pady=0)
            self.rp4_entry['Stop'] = tk.Button(self.MainFrame, text="Stop", command=lambda entry_id=y: self.action_stop(entry_id))
            self.rp4_entry['Stop'].grid(row=row, column=9 + column, padx=2, pady=0)
            self.rp4_entry['Restart'] = tk.Button(self.MainFrame, text="Restart_X", command=lambda entry_id=y: self.action_restart_xwindow(entry_id))
            self.rp4_entry['Restart'].grid(row=row, column=10 + column, padx=2, pady=0)
            self.rp4_table.append(self.rp4_entry)
            self.ip_list.append('')

        self.progressbar = ttk.Progressbar(top, orient="horizontal", length=500, mode="determinate")
        self.progressbar.place(relx=0.00, rely=0.98, relheight=0.99, relwidth=1)

        for task_id in range(0, 8):
            self.scan_proc_state.append(False)
        self.check_cpe_status()

    def on_configure(self,event):
        # update scrollregion after starting 'mainloop'
        # when all widgets are in canvas
        self.canvas.configure(scrollregion=self.canvas.bbox('all'))

    def on_mousewheel(self,event):
        shift = (event.state & 0x1) != 0
        scroll = -1 if event.delta > 0 else 1
        if shift:
            self.canvas.xview_scroll(scroll, "units")
        else:
            self.canvas.yview_scroll(scroll, "units")

    def start_logging(self):
        # Enable the logging to console and file
        for handler in logging.root.handlers[:]:
            logging.root.removeHandler(handler)
        logging.basicConfig(level=output_logging,
                            format='%(asctime)s: [%(levelname)s] %(message)s',
                            datefmt='%a, %d %b %Y %H:%M:%S',
                            filename='rp4_controller.log',
                            filemode='w')

        console = logging.StreamHandler()
        console.setLevel(output_logging)
        formatter = logging.Formatter('%(levelname)-4s %(message)s')
        console.setFormatter(formatter)
        logging.getLogger('').addHandler(console)

    def check_cpe_status(self):
        for x in range(0, self.row_total):
            self.ip_list[x] = ''
        self.scan_ip_list = []
        self.scan_task = []
        self.timeout = int(self.entry_timeout.get())

        for y in range(0, self.row_total):
            self.rp4_table[y]['Online'].configure(image=self.fail_gif)
            self.rp4_table[y]['Online'].image = self.fail_gif
            self.rp4_table[y]['Internet'].configure(image=self.fail_gif)
            self.rp4_table[y]['Internet'].image = self.fail_gif

        self.currentValue = 0
        logging.info('Start scan ARP in the network')
        self.btn_scan.config(state=tk.DISABLED)
        self.btn_internet.config(state=tk.DISABLED)
        self.btn_snmp.config(state=tk.DISABLED)

        for task_id in range(0, 8):
            self.scan_ip_list.append("")
            self.scan_network = self.entry_range.get()
            ip_start = task_id*32
            ip_end = ((task_id+1)*32)-1
            if ip_end>254:
                ip_end = 254
            self.scan_task.append(scan_process(self.scan_network,ip_start,ip_end,self.timeout,self.count))


        self.update()
        self.update_idletasks()

        for task_id in range(0, 8):
            while(self.scan_task[task_id].is_alive()==True):

                self.currentValue = self.currentValue + 1.25
                self.progressbar["value"] = self.currentValue
                self.progressbar.update()
                self.update()
                self.update_idletasks()
                self.after(500, )

            self.scan_proc_state = False
            self.scan_ip_list[task_id] = self.scan_task[task_id].client_list
            print (self.scan_task[task_id].client_list)

            for y in range(0, self.row_total):
                for client in self.scan_task[task_id].client_list:
                    if self.rp4_table[y]['MAC'].get() == client['mac']:
                        self.rp4_table[y]['IP'].delete(0, tk.END)
                        self.rp4_table[y]['IP'].insert(tk.END, client['ip'] + '\n')
                        self.ip_list[y] = client['ip']
                        self.rp4_table[y]['Online'].configure(image=self.pass_gif)
                        self.rp4_table[y]['Online'].image = self.pass_gif

            # print("IP List", self.ip_list)
            logging.info('Found IP list: %s', self.ip_list)

        self.currentValue = 100
        self.progressbar["value"] = self.currentValue
        self.progressbar.update()
        msgbox.showinfo("INFO", "Scan RP4 on Network are Finished")
        self.btn_scan.config(state=tk.NORMAL)
        self.btn_internet.config(state=tk.NORMAL)
        self.btn_snmp.config(state=tk.NORMAL)
        self.update()
        self.update_idletasks()

    def check_internet_status(self):
        logging.info('Start execute PING 8.8.8.8 on each RP4')
        self.currentValue = 0
        self.btn_scan.config(state=tk.DISABLED)
        self.btn_internet.config(state=tk.DISABLED)
        self.btn_snmp.config(state=tk.DISABLED)
        self.action_ping()
        self.update()
        self.update_idletasks()

    def check_traffic_status(self):
        proc_count = 0
        self.btn_scan.config(state=tk.DISABLED)
        self.btn_internet.config(state=tk.DISABLED)
        self.btn_snmp.config(state=tk.DISABLED)

        self.currentValue = 0
        self.progressbar["value"] = self.currentValue
        self.progressbar.update()
        self.update()
        self.update_idletasks()
        self.after(500, )

        #if self.scan_task.is_alive() == True or self.scan_proc_state == True:
        #    self.update()
        #    self.update_idletasks()
        #    self.alive_id = self.after(500, lambda: self.action_snmp())
        #else:
        count = 0
        self.snmp_thread_list = []
        self.currentValue = 0
        for y in range(0, self.row_total):
            if self.ip_list[y] != '':
                # print("Query SNMP:", self.ip_list[y])
                logging.info('Check wlan0 via SNMP on %s', self.ip_list[y])
                self.currentValue = self.currentValue + 5
                self.progressbar["value"] = self.currentValue
                self.progressbar.update()
                self.snmp_thread_list.append(snmp_process(self.ip_list[y]))
                proc_count = proc_count + 1
            else:
                self.snmp_thread_list.append('')
        total_proc_count = proc_count
        while proc_count > 0:
            for y in range(0, self.row_total):
                if self.snmp_thread_list[y] != '':
                    if self.snmp_thread_list[y].is_alive() == True:
                        self.update_idletasks()
                        self.update()
                        self.after(500)
                    else:
                        self.rp4_table[y]['wlan0_TX'].delete(0, tk.END)
                        self.rp4_table[y]['wlan0_RX'].delete(0, tk.END)
                        self.rp4_table[y]['wlan0_TX'].insert(tk.END, self.snmp_thread_list[y].wlan0_tx)
                        self.rp4_table[y]['wlan0_RX'].insert(tk.END, self.snmp_thread_list[y].wlan0_rx)
                        proc_count = proc_count - 1
                        self.snmp_thread_list[y] = ''

                        self.currentValue = self.currentValue + (100 / total_proc_count)
                        self.progressbar["value"] = self.currentValue
                        self.progressbar.update()
                        self.update()
                        self.update_idletasks()
                        self.after(500, )

        self.btn_scan.config(state=tk.NORMAL)
        self.btn_internet.config(state=tk.NORMAL)
        self.btn_snmp.config(state=tk.NORMAL)
        self.progressbar["value"] = 100
        self.progressbar.update()
        self.update()
        self.update_idletasks()
        self.after(500, )
        msgbox.showinfo("INFO", "Query throughput on RP4 are Finished")
        logging.info('Get wlan0 TX/RX via SNMP Finished')

    def action_ping(self):
        command = []
        proc_count = 0
        command.append("sudo ping 8.8.8.8 -c 3")
        self.retry = int(self.entry_count.get())

        self.currentValue = 0
        self.progressbar["value"] = self.currentValue
        self.progressbar.update()
        self.update()
        self.update_idletasks()

        #if self.scan_task.is_alive() == True or self.scan_proc_state == True:
        #    self.update()
        #    self.update_idletasks()
        #    self.alive_id = self.after(500, lambda: self.action_ping())
        #else:
        self.ping_thread_list = []
        for y in range(0, self.row_total):
            #self.currentValue = self.currentValue + 5
            #self.progressbar["value"] = self.currentValue
            self.progressbar.update()
            if self.ip_list[y] != '':
                logging.info('Start execute PING 8.8.8.8 on %s', self.ip_list[y])
                # print("Connect SSH:", self.ip_list[y])
                self.ping_thread_list.append(ssh_process(self.ip_list[y], command,self.retry))
                proc_count = proc_count + 1
                self.after(1000)
                self.update()
                self.update_idletasks()
            else:
                self.ping_thread_list.append('')

        total_proc_count = proc_count

        while proc_count > 0:
            for y in range(0, self.row_total):
                if self.ping_thread_list[y] != '':
                    if self.ping_thread_list[y].is_alive() == True:
                        self.update_idletasks()
                        self.update()
                        self.after(500)
                    else:
                        if 'time=' in self.ping_thread_list[y].stdout_output:
                            self.rp4_table[y]['Internet'].configure(image=self.pass_gif)
                            self.rp4_table[y]['Internet'].image = self.pass_gif
                            proc_count = proc_count - 1
                            self.ping_thread_list[y] = ''

                            self.currentValue = self.currentValue + (100/total_proc_count)
                            self.progressbar["value"] = self.currentValue
                            self.progressbar.update()
                            self.update()
                            self.update_idletasks()
                            self.after(500, )

                        else:
                            if self.ping_thread_list[y].retry_count<1:
                                self.rp4_table[y]['Internet'].configure(image=self.fail_gif)
                                self.rp4_table[y]['Internet'].image = self.fail_gif
                                proc_count = proc_count - 1
                                self.ping_thread_list[y] = ''
                            else:
                                last_retry_count = self.ping_thread_list[y].retry_count
                                self.ping_thread_list[y] = ssh_process(self.ip_list[y], command, last_retry_count)
                                self.ping_thread_list[y].retry_count = last_retry_count - 1
                                logging.info('retry SSH connection on: %s,%s', self.ip_list[y], str(self.ping_thread_list[y].retry_count))

        self.currentValue = 100
        self.progressbar["value"] = self.currentValue
        self.progressbar.update()
        self.btn_scan.config(state=tk.NORMAL)
        self.btn_internet.config(state=tk.NORMAL)
        self.btn_snmp.config(state=tk.NORMAL)
        self.update()
        self.update_idletasks()
        msgbox.showinfo("INFO", "Check RP4 Internet Connection are Finished")
        logging.info('PING test Finished')

    def action_start(self, rp4_id):
        command_list = []
        ssh_thread_list = []
        client_no = 0

        command_list.append("export DISPLAY=:0.0; xterm -e /bin/bash -l -c \"/opt/client/pingtest.sh wlan0\"")
        # command_list.append("export DISPLAY=:0.0; xterm & chromium-browser https://www.youtube.com/watch?v=Hu1FkdAOws0")
        command_list.append("/bin/bash /home/pi/start_test.sh")

        if rp4_id =="all":
            for id in range(0,self.row_total):
                if self.ip_list[id]!="":
                    ssh_thread_list.append(ssh_process(self.ip_list[id], command_list, 3))
                    logging.info('Execute start test via SSH on %s', self.ip_list[id])
                    while ssh_thread_list[client_no].is_alive() == True:
                        self.update_idletasks()
                        self.update()
                        self.after(500)
                    client_no +=1
            msgbox.showinfo("INFO", "Start Finished")
        else:
            if self.ip_list[rp4_id] == '':
                msgbox.showerror("ERROR", "No IP address found")
                return
            ssh_thread_list.append(ssh_process(self.ip_list[rp4_id], command_list,3))
            while ssh_thread_list[client_no].is_alive() == True:
                self.update_idletasks()
                self.update()
                self.after(500)
            msgbox.showinfo("INFO", "Start Finished")
            logging.info('Execute start test via SSH on %s', rp4_id)

    def action_stop(self, rp4_id):
        command_list = []
        ssh_thread_list = []
        client_no = 0

        command_list.append("killall xterm")
        command_list.append("killall chromium")
        command_list.append("pkill chromium-browse")

        if rp4_id =="all":
            for id in range(0,self.row_total):
                if self.ip_list[id]!="":
                    ssh_thread_list.append(ssh_process(self.ip_list[id], command_list, 3))
                    logging.info('Execute stop test via SSH on %s', self.ip_list[id])
                    while ssh_thread_list[client_no].is_alive() == True:
                        self.update_idletasks()
                        self.update()
                        self.after(500)
                    client_no += 1
                    msgbox.showinfo("INFO", "Stop Finished")
        else:
            if self.ip_list[rp4_id] == '':
                msgbox.showerror("ERROR", "No IP address found")
                return
            ssh_thread_list.append(ssh_process(self.ip_list[rp4_id], command_list, 3))
            while ssh_thread_list[client_no].is_alive() == True:
                self.update_idletasks()
                self.update()
                self.after(500)
            msgbox.showinfo("INFO", "Stop Finished")
            logging.info('Execute stop test via SSH on %s', rp4_id)

    def action_reboot(self, rp4_id):
        command_list = []
        ssh_thread_list = []
        client_no = 0
        command_list.append("sudo reboot")

        if rp4_id =="all":
            for id in range(0,self.row_total):
                if self.ip_list[id]!="":
                    ssh_thread_list.append(ssh_process(self.ip_list[id], command_list, retry=3))
                    logging.info('Execute reboot via SSH on %s', self.ip_list[id])
                    while ssh_thread_list[client_no].is_alive() == True:
                        self.update_idletasks()
                        self.update()
                        self.after(500)
                    client_no += 1
            msgbox.showinfo("INFO", "Reboot Finished")
        else:
            if self.ip_list[rp4_id] == '':
                msgbox.showerror("ERROR", "No IP address found")
                return
            ssh_thread_list.append(ssh_process(self.ip_list[rp4_id], command_list, retry=3))
            while ssh_thread_list[client_no].is_alive() == True:
                self.update_idletasks()
                self.update()
                self.after(500)
            msgbox.showinfo("INFO", "Reboot Finished")
            logging.info('Execute reboot via SSH on %s', rp4_id)

    def action_restart_xwindow(self, rp4_id):
        command_list = []
        ssh_thread_list = []
        client_no = 0

        command_list.append("sudo service lightdm restart")

        if rp4_id =="all":
            for id in range(0,self.row_total):
                if self.ip_list[id]!="":
                    ssh_thread_list.append(ssh_process(self.ip_list[id], command_list,3))
                    logging.info('Execute reboot via SSH on %s', self.ip_list[id])
                    while ssh_thread_list[client_no].is_alive() == True:
                        self.update_idletasks()
                        self.update()
                        self.after(500)
                    client_no+=1
            msgbox.showinfo("INFO", "Restart X-Windows Finished")
        else:
            if self.ip_list[rp4_id] == '':
                msgbox.showerror("ERROR", "No IP address found")
                return
            ssh_thread_list.append(ssh_process(self.ip_list[rp4_id], command_list,3))
            while ssh_thread_list[client_no].is_alive() == True:
                self.update_idletasks()
                self.update()
                self.after(500)
            msgbox.showinfo("INFO", "Restart X-Windows Finished")
            logging.info('Execute reboot via SSH on %s', rp4_id)

    def action_command(self, rp4_id):
        self.command_output = ''
        self.text_output.delete('1.0', tk.END)
        ssh_thread_list = []
        client_no = 0
        # self.convert_list()
        command_list = []

        self.command_input = self.command_text.get("1.0", tk.END)
        command_list = list(filter(None, self.command_input.split('\n')))
        for client in self.scan_ip_list:
            ssh_thread_list.append(ssh_process(client['ip'], command_list))
            ssh_thread_list[client_no].join()
            self.command_output = self.command_output + "\n" + "IP: " + client['ip'] + "\n" + \
                                  ssh_thread_list[client_no].stderr_output + "\n" + \
                                  ssh_thread_list[client_no].stdout_output
            client_no = client_no + 1

    def convert_list(self):
        ip_list = {}
        self.scan_ip_list = []
        table = self.list_IP_addr.get("1.0", tk.END)
        hosts = list(filter(None, table.split("\n")))
        for entry in hosts:
            ip_list['ip'] = entry
            ip_list['mac'] = ''
            self.scan_ip_list.append(ip_list)

    def csv_read(self, filename):
        try:
            table = []
            logging.info('open filename = ' + filename)
            file = open(filename, mode="r", errors='ignore')
            #table = file.read().splitlines()
            for line in file:
                line = line.rstrip()
                table.append(line)
            file.close()
            if len(table)<32:
                for empty_line in range(32-len(table)):
                    table.append("00:00:00:00:00:00")
            return table
        except:
            logging.info("MAC address file not found, use default mac address")
            return self.mac_list

class scan_process(Thread):
    result_list = []
    client_list = []
    ip_addr = ''

    def __init__(self, ip_network, ip_start, ip_end, timeout, count):
        super().__init__()
        self.ip_network = ip_network
        self.ip_start = ip_start
        self.ip_end = ip_end
        self.scan_timeout = timeout
        self.daemon = True
        self.scan_count = count
        self.start()

    def run(self):
        self.client_list = []
        socket.setdefaulttimeout(1)
        socket.timeout(1)

        self.ip_prefix_list = self.ip_network.split("/")[0].split(".")
        self.ip_prefix = '.'.join(self.ip_prefix_list[0:3])
        for x in range(0, self.scan_count):
            for ip_count in range(self.ip_start,self.ip_end+1):
                arp_request = scapy.ARP(pdst=self.ip_prefix + "." + str(ip_count),op=1)
                #arp_request = scapy.ARP(pdst=self.ip_addr, op=1)
                # rarp_request = scapy.ARP(op=3, hwsrc="50:3e:aa:5e:e8:fd", hwdst=mac)
                broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
                arp_request_broadcast = broadcast / arp_request
                answered_list = scapy.srp(arp_request_broadcast, timeout=(self.scan_timeout/1000),iface="LAN",verbose=False)[0]
                for element in answered_list:
                    client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
                    # hostname = socket.gethostbyaddr(client_dict['ip'])[0]
                    # client_dict["hostname"] = ""
                    #if "dc:a6:32" in client_dict['mac']:
                    if client_dict['ip'] not in self.client_list:
                        self.client_list.append(client_dict)
                        print(client_dict['mac'], client_dict['ip'])
        return self.client_list

            #time.sleep(0.2)

    def print_result(self, results_list):
        print("IP\t\t\tMAC Address\n-----------------------------------------")
        for client in results_list:
            print(client["ip"] + "\t\t" + client["mac"] + "\t\t" + str(client["hostname"]))

class snmp_process(Thread):
    wlan0_tx = 0
    wlan0_rx = 0
    snmp_host = ''

    def __init__(self, ip):
        super().__init__()
        self.daemon = True
        self.snmp_host = ip
        self.start()

    def run(self):
        try:
            old_in_octet, old_out_octet = self.query_snmp()
            time.sleep(3)
            new_in_octet, new_out_octet = self.query_snmp()
            self.wlan0_rx = round(((new_in_octet - old_in_octet) * 8) / (1024 * 1024 * 3), 3)
            self.wlan0_tx = round(((new_out_octet - old_out_octet) * 8) / (1024 * 1024 * 3), 3)
        except Exception as ex:
            print("SNMP Error:",repr(ex))
        # print(self.wlan0_rx)
        # print(self.wlan0_tx)

    def query_snmp(self):
        value_list = []
        errorIndication, errorStatus, errorIndex, varBinds = next(
            getCmd(SnmpEngine(),
                   CommunityData('public'),
                   UdpTransportTarget((self.snmp_host, 161)),
                   ContextData(),
                   ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.10.3')),
                   ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.16.3')))
        )

        if errorIndication:
            print(errorIndication)
        elif errorStatus:
            print('%s at %s' % (errorStatus.prettyPrint(),
                                errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
        else:
            for oid, value in varBinds:
                value_list.append(int(value))
        return value_list

class ssh_process(Thread):
    stderr_output = ''
    stdout_output = ''
    stdin_input = ''
    ip_addr = ''
    command_req = []
    error_flag = False
    retry_count = 3

    def __init__(self, ip, command,retry):
        super().__init__()
        self.daemon = True
        self.ip_addr = ip.replace('\n', '')
        self.command_req = command
        self.retry_count = int(retry)
        self.start()

    def run(self):
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        stdin = ''
        stdout = ''
        stderr = ''
        try:
            # ssh_client.connect(hostname=self.ip_addr, port=22, username='pi', password='raspberry',timeout=3,
            #                   auth_timeout=3, banner_timeout=3)

            ssh_client.connect(hostname=self.ip_addr, port=22, username='pi', password='raspberry', timeout=5,
                               auth_timeout=5, banner_timeout=5)
            logging.info("Connect to SSH server: %s", self.ip_addr)
            for entry in self.command_req:
                entry = entry + "\n"
                if ('xterm' in entry):
                    stdin, stdout, stderr = ssh_client.exec_command(bufsize=-1, timeout=5, command=entry)
                    time.sleep(1)
                else:
                    stdin, stdout, stderr = ssh_client.exec_command(command=entry,  timeout=5)
                    self.stderr_output = stderr.read().decode()
                    self.stdout_output = stdout.read().decode()
                    time.sleep(1)
            # print("Err:",self.stderr_output)
            # print("Out:",self.stdout_output)
            self.error_flag = False
        except:
            # print("Err:", stderr.read().decode())
            # print("Out:", stdout.read().decode())
            logging.info("Connect SSH fail: %s", self.ip_addr)
            self.error_flag = True
        ssh_client.close()

if __name__ == '__main__':
    app = gui_app()
    app.mainloop()
    sys.exit(0)
