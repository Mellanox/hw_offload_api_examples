#!/bin/bash

k=10
m=4
w=4
DURATION=20
CORES=12
N_CALC_ARR=(1 2 4 16 32 64)
BLOCK_SIZE_ARR=(1 16 256 512 1024 4096)
INFLIGHT_CALCS_ARR=(1 4 16 32 64)

OUTPUT=/tmp/ibv_ec_perf_log

cpu_start=$((DURATION/4))
cpu_dur=$((DURATION/2))
cpu_int=1
cpu_data=/tmp/data
cpu_data_txt=/tmp/data_txt
cores_total=12

function usage {
    echo " "
    echo "Usage: `basename $0` [-a|-b|-c|-d|-i|-k|-m|-q|-r|-s|-w|-h]"
    echo " "
    echo "Produce performance report for sync/async in-memory encode"
    echo " "
    echo "-d <VAL>        device (mandatory)"
    echo "-i <VAL>        interface (mandatory)"
    echo "-k <VAL>        k"
    echo "-m <VAL>        m"
    echo "-w <VAL>        w"
    echo "-r <VAL>        duration in seconds"
    echo "-c <VAL>        number of cores to use"
    echo "-q <VAL,VAL>    number of calcs(qps) per core"
    echo "-b <VAL,VAL>    block sizes to use (in KB)"
    echo "-l <VAL,VAL>    number of inflight calcs (qdepth)"
    echo "-a              use asyncronuous encode"
    echo "-s              use sw encode(Jerasure)"
    echo "-h              show brief help"
    echo " "
    exit
}

while getopts "b:c:d:i:k:l:m:q:r:w:ash" o; do
   case "${o}" in
       a)
           async=1
           ;;
       s)
           sw=1
           ;;
       k)
           k=${OPTARG}
           ;;
       m)
           m=${OPTARG}
           ;;
       w)
           w=${OPTARG}
           ;;
      r)
          DURATION=${OPTARG}
          ;;
      d)
          DEVICE=${OPTARG}
          ;;
      i)
          INTERFACE=${OPTARG}
          ;;
      c)
           CORES=${OPTARG}
           ;;
       q)
           N_CALC_ARR=($(echo $OPTARG | tr ',' "\n"))
           ;;
       b)
           BLOCK_SIZE_ARR=($(echo $OPTARG | tr ',' "\n"))
           ;;
       l)
           INFLIGHT_CALCS_ARR=($(echo $OPTARG | tr ',' "\n"))
           ;;
       h)
           usage
           ;;
       *)
           usage
           ;;
   esac
done

function check_params {
    if [[ -z $DEVICE || -z $INTERFACE ]]; then
        echo "Missing mandatory parameter: DEVICE/INTERFACE"
        usage
        exit
    fi

    if [[ ! -z $async ]]; then
        app="ibv_ec_perf_async"
    else
        app="ibv_ec_perf_sync"
        unset INFLIGHT_CALCS_ARR
    fi
}

function wait_for {
        while [ `ps -ef | grep $1 | wc -l` -gt 1 ]; do
                sleep 1
        done
}

function run {
    local bs=$1
    local n_calcs=$2
    local inf=$3

    for core in `seq 1 1 $CORES`; do
        cmd="taskset -c $(($core-1)) "
        cmd+="$app -r $DURATION -f $(($core-1)) -i $DEVICE "
        cmd+="-k $((k)) -m $((m)) -w $((w)) -s $((bs*1024*k)) "
        if [[ ! -z $async ]]; then
            cmd+="-l $inf -n"
        fi
        if [[ ! -z $sw ]]; then
            cmd+="-S "
        fi

        cmd+=">> $OUTPUT &"

        for i in `seq 1 1 $n_calcs`; do
           eval $cmd
        done
    done
}

function print_result {
    cat $OUTPUT | awk '{s=s+$1}END{print s}'
    echo "" > $OUTPUT
}

function get_cores_total {
    cores_total=`cat /proc/cpuinfo | awk '/^processor/{print $3}' | tail -1`
    cores_total=$((cores_total+1))
}

function measure_cpu {
    rm -f $cpu_data
    rm -f $cpu_data_txt
    sleep $cpu_start
    sar -u $cpu_int $cpu_dur -o $cpu_data > /dev/null 2>&1
    sar -f $cpu_data > $cpu_data_txt
    line=`awk 'NR==1; END{print}' $cpu_data_txt`
    cpu_idle=`echo $line | awk '{split($0,a," "); print a[15]}'`
    cpu_util=$(echo $cpu_idle|awk '{printf "%4.3f\n",100-$1}')
    # measure cpu utilization relatively to the number of used cores
    cpu_util=$(echo $cpu_util $cores_total $CORES| awk '{printf "%4.3f\n",$1*$2/$3}')
}

function set_affinity {
    cmd="set_irq_affinity_cpulist.sh 0-$((CORES - 1)) $INTERFACE  > /dev/null 2>&1"
    eval $cmd
}

function run_test {
    local bs=$1
    local n_calcs=$2
    local inflights=$3

    echo -n "  $n_calcs               $bs                     $inflights                  "
    run $bs $n_calcs $inflights
    measure_cpu
    echo -n "$cpu_util               "
    wait_for $app
    print_result
}

check_params
pkill $app
get_cores_total
CORES=`echo $(($CORES < $cores_total ? $CORES : $cores_total))`
set_affinity

echo "" > $OUTPUT
echo "k=$k m=$m cores=$CORES"
echo "n-calcs        block-size[KB]        inflights            cpu[%]              bw[MB/sec]"

for bs in ${BLOCK_SIZE_ARR[@]} ; do
    for n_calcs in ${N_CALC_ARR[@]} ; do
        if [[ ! -z $async ]]; then
            for inflights in ${INFLIGHT_CALCS_ARR[@]}; do
                run_test $bs $n_calcs $inflights
            done
         else
            run_test $bs $n_calcs
        fi
    done
done

