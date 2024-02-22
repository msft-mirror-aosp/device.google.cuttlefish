#!/bin/bash
# Copyright 2024 Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

color_cyan="\033[0;36m"
color_plain="\033[0m"
color_yellow="\033[0;33m"

# validate number of arguments
if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  echo "This script requires 1 mandatory and 1 optional parameters, server address and optionally number of instances to invoke"
  exit 1
fi

# map arguments to variables
# $1: ARM server address
# $2: Instance number (Optional, default is 1)
server=$1
if [ "$#" -eq 2 ]; then
 num_instances=$2
else
 num_instances=1
fi

# set img_dir and cvd_host_tool_dir
img_dir=${ANDROID_PRODUCT_OUT:-$PWD}
cvd_host_tool_dir=${ANDROID_HOST_OUT:+"$ANDROID_HOST_OUT/../linux_musl-arm64"}
cvd_host_tool_dir=${cvd_host_tool_dir:-$PWD}

# upload artifacts into ARM server
cvd_home_dir=cvd_home
ssh $server -t "mkdir -p ~/.cvd_artifact; mkdir -p ~/$cvd_home_dir"
if [ -f $img_dir/required_images ]; then
  rsync -aSvch --recursive $img_dir --files-from=$img_dir/required_images $server:~/$cvd_home_dir --info=progress2
else
  rsync -aSvch --recursive $img_dir/bootloader $img_dir/*.img $server:~/$cvd_home_dir --info=progress2
fi

# upload cvd-host_package.tar.gz into ARM server
temp_dir=/tmp/cvd_dist
rm -rf $temp_dir
mkdir -p $temp_dir
if [ -d $cvd_host_tool_dir/cvd-host_package ]; then
  echo "Use contents in cvd-host_package dir"
  pushd $cvd_host_tool_dir/cvd-host_package > /dev/null
  tar -cf $temp_dir/cvd-host_package.tar ./*
  popd > /dev/null
  pigz -R $temp_dir/cvd-host_package.tar
elif [ -f $cvd_host_tool_dir/cvd-host_package.tar.gz ]; then
  echo "Use contents in cvd-host_package.tar.gz"
  # re-compress with rsyncable option
  # TODO(b/275312073): remove this if toxbox supports rsyncable
  pigz -d -c $cvd_host_tool_dir/cvd-host_package.tar.gz | pigz -R > $temp_dir/cvd-host_package.tar.gz
else
  echo "There is neither cvd-host_package dir nor cvd-host_package.tar.gz"
  exit 1
fi
rsync -avch $temp_dir/cvd-host_package.tar.gz $server:~/$cvd_home_dir --info=progress2

# run docker instance
container_id=$(ssh $server -t "docker run --rm --privileged -P -d cuttlefish")
container_id=${container_id//$'\r'} # to remove trailing ^M
echo -e "${color_cyan}Booting container $container_id${color_plain}"

# set trap to stop docker instance
trap cleanup SIGINT
cleanup() {
  echo -e "${color_yellow}SIGINT: stopping the launch instances${color_plain}"
  ssh $server "docker kill $container_id"
}

# extract Host Orchestrator Port
docker_inspect=$(ssh $server "docker inspect --format='{{json .NetworkSettings.Ports }}' $container_id")
docker_host_orchestrator_port_parser_script='
import sys, json;
json_raw=input()
data = json.loads(json_raw)
for k in data:
  original_port = int(k.split("/")[0])
  assigned_port = int(data[k][0]["HostPort"])
  if original_port == 2443:
    print(assigned_port)
    break
'
docker_host_orchestrator_port=$(echo $docker_inspect | python -c "$docker_host_orchestrator_port_parser_script")
host_orchestrator_url=https://localhost:$docker_host_orchestrator_port
echo -e "Extracting host orchestrator port in docker instance"

# create user artifact directory
create_user_artifacts_dir_script="ssh $server curl -s -k -X POST ${host_orchestrator_url}/userartifacts | jq -r '.name'"
user_artifacts_dir=$($create_user_artifacts_dir_script)
while [ -z "$user_artifacts_dir" ]; do
  echo -e "Failed to create user_artifacts_dir, retrying"
  sleep 1
  user_artifacts_dir=$($create_user_artifacts_dir_script)
done
echo -e "Succeeded to create user_artifacts_dir"

# upload artifacts and cvd-host_pachage.tar.gz into docker instance
ssh $server \
  "for filename in \$(ls $cvd_home_dir); do \
     absolute_path=\$HOME/$cvd_home_dir/\$filename && \
     size=\$(stat -c%s \$absolute_path) && \
     echo Uploading \$filename\\(size:\$size\\) ... && \
     curl -s -k --location -X PUT $host_orchestrator_url/userartifacts/$user_artifacts_dir \
       -H 'Content-Type: multipart/form-data' \
       -F chunk_number=1 \
       -F chunk_total=1 \
       -F chunk_size_bytes=\$size \
       -F file=@\$absolute_path; \
   done"
echo -e "Done"

# start Cuttlefish instance on top of docker instance
echo -e "Starting Cuttlefish"
ssh $server "curl -s -k -X POST $host_orchestrator_url/cvds \
  -H 'Content-Type: application/json' \
  -d '{\"cvd\": {\"build_source\": {\"user_build_source\": {\"artifacts_dir\": \"$user_artifacts_dir\"}}}, \"additional_instances_num\": $(($num_instances-1))}'
"

# Web UI port is 3443 instead 1443 because there could be a running operator or host orchestrator in this machine as well.
web_ui_port=3443
echo -e "Web UI port: $web_ui_port. ${color_cyan}Please point your browser to https://localhost:$web_ui_port for the UI${color_plain}"

# sets up SSH port forwarding to the remote server for various ports and launch cvd instance
for instance_num in $(seq 1 $num_instances); do
  device_name="cvd_$instance_num"
  adb_port=$((6520+$instance_num-1))
  echo -e "$device_name is using adb port $adb_port. Try ${color_cyan}adb connect 127.0.0.1:${adb_port}${color_plain} if you want to connect to this device"
done

docker_port_parser_script='
import sys, json;
web_ui_port = int(sys.argv[1])
max_instances = 100
num_instance = int(sys.argv[2])
json_raw=input()
data = json.loads(json_raw)
for k in data:
  original_port = int(k.split("/")[0])
  assigned_port = int(data[k][0]["HostPort"])
  if original_port == 1443:
    original_port = web_ui_port
  elif original_port in (1080, 2080, 2443): # Do not expose other operator or host orchestrator port beyond ARM server
    continue
  elif original_port >= 6520 and original_port <= 6520 + max_instances:
    if original_port - 6520 >= num_instance:
      continue
  print(f"-L {original_port}:127.0.0.1:{assigned_port}", end=" ")
'
ports_forwarding=$(echo $docker_inspect | python -c "$docker_port_parser_script" $web_ui_port $num_instances)
echo -e $ports_forwarding
echo "Set up ssh ports forwarding: $ports_forwarding"
echo -e "${color_yellow}Please stop the running instances by ctrl+c${color_plain}"
ssh $server $ports_forwarding "docker logs -f $container_id"
