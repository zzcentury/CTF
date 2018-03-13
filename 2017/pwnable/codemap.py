import subprocess
 
def cmp(a):
    if a[0]&gt;':':
        return 999999
    snum,string=a.split(' ')
    num=int(snum)
    return num
 
argv=['D:\\dump4.exe']
p=subprocess.Popen(args=argv,stdout=subprocess.PIPE)
text=p.communicate()
st=text[0].splitlines()
mylist=[]
for line in st:
    line=line.decode('utf-8')
    mylist.append(line)
 
f=open("output.txt","w")
dist=sorted(mylist,key=cmp)
for ele in dist:
    f.write(ele+"\n")