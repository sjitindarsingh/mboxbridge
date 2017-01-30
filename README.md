Copyright 2016 IBM

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

# Intro
The autotools of this requires the autoconf-archive package for your
system

This is a protocol description using the mailbox registers on
Aspeed 2400/2500 chips for host to BMC communication. The mailbox
consists of 16 data registers (see Layout for their use). A pair of
control registers, one accessible by the host the other by the BMC.
Finally some interrupt enable and status registers which can enable an
interrupt to be raised per write to each data register, for BMC and
host. That is, two 8 byte registers where each byte represents a data
register and if an interrupt should fire on write along with two 8
byte registers to act as a mask for these interrupts.

### General use
Messages always originate from the host to the BMC. There are special
cases for a back channel for the BMC to pass new information to the
host which will be discussed later.

To initiate a request the host must set a command code (see
Commands) into byte 0 of the mailbox registers. It is also the hosts
responsibility to generate a unique sequence number into mailbox
register 1. After this any command specific data should be written
(see Layout). The host must then generate an interrupt to the BMC by
using bit 0 of its control register and wait for an interrupt in the
response. Generating an interrupt automatically sets bit 7 of the
corresponding control register. This bit can be used to poll for
messages.

On receiving an interrupt (or polling on bit 7 of its Control
Register) the BMC should read the message from the general registers
of the mailbox and perform the necessary action before responding. On
responding the BMC must ensure that the sequence number is the same as
the one in the request from the host. The BMC must also ensure that
mailbox byte 13 is a valid response code (see Responses). The BMC
should then use its control register to generate an interrupt for
the host to notify of it of a response.


### BMC to host
BMC to host communication is also possible for notification of events
from the BMC. This requires that the host have interrupts enabled on
mailbox byte 15 (or otherwise poll on byte 7 of mailbox status
register 1). On receiving such a notification the host should read
mailbox byte 15 to determine which bit has been set in order to
determine the message, see BMC Event notifications in Commands in
detail. After performing the necessary action the host should send a
BMC_EVENT_ACK message to the BMC with which bit it has actioned.

---

## Layout
```
Byte 0: COMMAND
Byte 1: Sequence
Byte 2-12: Data
Byte 13: Response code
Byte 14: Host controlled status reg
Byte 15: BMC controlled status reg
```
## Commands
```
RESET_STATE
GET_MBOX_INFO
CLOSE_WINDOW
GET_FLASH_INFO
CREATE_READ_WINDOW
CREATE_WRITE_WINDOW
MARK_WRITE_DIRTY
WRITE_FLUSH
BMC_EVENT_ACK
```
## Sequence
Unique message sequence number to be allocated by the host at the
start of a command/response pair. The BMC must ensure the responses to
a particular message contain the same sequence number than was in the
request from the host.

## Responses
```
SUCCESS
PARAM_ERROR
WRITE_ERROR
SYSTEM_ERROR
TIMEOUT
```

## Information
- Interrupts via control regs
- All multibyte messages are LSB (little endian)
- All responses must have a valid return code in byte 13

### Commands in detail
```
	Command:
		RESET_STATE
		Data:
			-
		Response:
			-
		Notes:
			This command is designed to inform the BMC that it should put
			host LPC mapping back in a state where the SBE will be able to
			use it. Currently this means pointing back to BMC flash
			pre mailbox protocol. Final behavour is still TBD.


	Command:
		GET_MBOX_INFO
		Data:
			Data 0: API version

		Response:
			Data 0: API version
			Data 1-2: read window size in block size
			Data 3-4: write window size in block size
			Data 5: Block size in power of two.


	Command:
		CLOSE_WINDOW
		Data:
			-
		Response:
			-
		Notes:
			Close active window. Renders the LPC mapping unusable.


	Command:
		GET_FLASH_INFO
		Data:
			-
		Response:
			Data 0-3: Flash size in bytes
			Data 4-7: Erase granule in bytes


	Command:
		CREATE_READ_WINDOW
		Data:
			Data 0-1: Read window offset in block size
		Response:
			Data 0-1: Read window position in block size
		Notes:
			Offset is the offset within the flash, always specified
			  from zero.
			Position is where flash at the requested off is mapped on
			  the LPC bus as viewed from the host.


	Command:
		CREATE_WRITE_WINDOW
		Data:
			Data 0-1: Write window offset in block size
		Response:
			Data 0-1: Write window position in block size
		Notes:
			Offset is the offset within the flash, always specified
			  from zero.
			Position is where flash at the requested off is mapped on
			  the LPC bus as viewed from the host.


	Command:
		MARK_WRITE_DIRTY
		Data:
			Data 0-1: Where within window in block size
			Data 2-5: Number of dirty bytes
		Response:
			-
		Notes:
			Where within the window is the index of the first dirty
			block within the window - zero refers to the first block of
			the mapping.
			This command marks bytes as dirty but does not nessesarily
			flush them to flash. This command is expected not to block
			during a write.


	Command
		WRITE_FLUSH
		Data:
			Data 0-1: Where within window in block size
			Data 2-5: Number of dirty bytes
		Response:
			-
		Notes:
			Where within the window is the index of the first dirty
			block within the window - zero refers to the first block of
			the mapping.
			Number of dirty bytes can be zero, this would result in
			writing all bytes previously marked as dirty.
			This command will block untill all dirty bytes have been
			written to the backing store.


	Command:
		BMC_EVENT_ACK
		Data:
			Bits in the BMC status reg (register 15) to ack
		Response:
			*clears the bits in register 15*
			-
		Notes:
			The host will use this command to acknoledge BMC events
			supplied in mailbox register 15.


	BMC notifications:
		If the BMC needs to tell the host something then it simply
		writes to Byte 15. The host should have interrupts enabled
		on that register, or otherwise be polling it.
		 -[bit 0] BMC reboot. A BMC reboot informs the host that its
		  windows/dirty bytes/in flight commands will be lost and it
		  should attempt to reopen windows and rewrite any data it had
		  not flushed.
		Futhur details TBD
```
