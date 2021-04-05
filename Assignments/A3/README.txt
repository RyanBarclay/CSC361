THIS IS THE README 


Notes: I had some bugs with trying to get UDP fragmenting to work. I also could not get the Windows version of the trace route to work. 

Though it should work perfectly for traceroutes without fragmenting present. 

To run:
    *un zip the file
    *go into a3 folder.
    *once there you can place the files you would like to test in the PcapFiles folder or not, this is up to you.
    *After, go into src directory.
    * to run type either:

        python3 main.py 
            * this will run all cap files in the ../PcapFiles directory wth prompts
        or 

        python3 main.py <PcapFile1> <PcapFile2> <PcapFile...> 
            * or you can pass pcap files as arguments 

Again: code will not behave with windows or fragments inside traceroute
    ... apologies 