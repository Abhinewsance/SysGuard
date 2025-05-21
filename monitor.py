import psutil

def get_process_info():
    process_list = []
    for proc in psutil.process_iter(['pid', 'name', 'username']):
        try:
            process_info = proc.info
            process_list.append(process_info)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return process_list
