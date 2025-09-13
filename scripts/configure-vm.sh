#!/bin/bash

# VM Configuration Script for InfiniService
# Automates VirtIO serial device configuration for different hypervisors

set -euo pipefail

# Script configuration
SCRIPT_NAME="$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="/tmp/configure-vm-$(date +%Y%m%d-%H%M%S).log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Dependency checking function
require_cmd() {
    local cmd="$1"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        case "$cmd" in
            virsh)
                error "$cmd not found. Install with: sudo apt-get install libvirt-clients (Ubuntu/Debian) or sudo yum install libvirt-client (RHEL/CentOS)"
                ;;
            socat)
                error "$cmd not found. Install with: sudo apt-get install socat (Ubuntu/Debian) or sudo yum install socat (RHEL/CentOS)"
                ;;
            VBoxManage)
                error "$cmd not found. Install VirtualBox from https://www.virtualbox.org/"
                ;;
            timeout)
                error "$cmd not found. Install with: sudo apt-get install coreutils (usually pre-installed)"
                ;;
            xmlstarlet)
                error "$cmd not found. Install with: sudo apt-get install xmlstarlet (Ubuntu/Debian) or sudo yum install xmlstarlet (RHEL/CentOS)"
                ;;
            semanage)
                error "$cmd not found. Install with: sudo apt-get install policycoreutils-python-utils (Ubuntu/Debian) or sudo yum install policycoreutils-python (RHEL/CentOS)"
                ;;
            *)
                error "$cmd not found. Please install $cmd and try again."
                ;;
        esac
    fi
}

# Logging function
log() {
    echo -e "${1}" | tee -a "$LOG_FILE"
}

error() {
    log "${RED}ERROR: ${1}${NC}"
    exit 1
}

warning() {
    log "${YELLOW}WARNING: ${1}${NC}"
}

info() {
    log "${BLUE}INFO: ${1}${NC}"
}

success() {
    log "${GREEN}SUCCESS: ${1}${NC}"
}

# Usage information
usage() {
    cat << EOF
Usage: $SCRIPT_NAME [OPTIONS] COMMAND

VM Configuration Script for InfiniService VirtIO Setup

COMMANDS:
    detect              Detect current hypervisor environment
    configure           Configure VirtIO for detected hypervisor
    validate            Validate existing VirtIO configuration
    generate            Generate configuration files
    test                Test VirtIO connectivity
    diagnose            Run comprehensive diagnostics

OPTIONS:
    -h, --help          Show this help message
    -v, --verbose       Enable verbose output
    -d, --dry-run       Show what would be done without making changes
    -f, --force         Force configuration even if validation fails
    --vm-name NAME      Specify VM name (required for some operations)
    --hypervisor TYPE   Force hypervisor type (qemu|vmware|vbox)
    --socket-path PATH  Custom socket path for QEMU/KVM
    --backup            Create backup before making changes

EXAMPLES:
    $SCRIPT_NAME detect
    $SCRIPT_NAME configure --vm-name "infinibay-vm"
    $SCRIPT_NAME generate --hypervisor qemu --vm-name "test-vm"
    $SCRIPT_NAME validate --vm-name "infinibay-vm"
    $SCRIPT_NAME test --vm-name "infinibay-vm"

For detailed configuration examples, see: docs/vm-configuration.md
EOF
}

# Parse command line arguments
VERBOSE=false
DRY_RUN=false
FORCE=false
BACKUP=false
VM_NAME=""
HYPERVISOR=""
SOCKET_PATH=""
COMMAND=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            exit 0
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -d|--dry-run)
            DRY_RUN=true
            shift
            ;;
        -f|--force)
            FORCE=true
            shift
            ;;
        --backup)
            BACKUP=true
            shift
            ;;
        --vm-name)
            VM_NAME="$2"
            shift 2
            ;;
        --hypervisor)
            HYPERVISOR="$2"
            shift 2
            ;;
        --socket-path)
            SOCKET_PATH="$2"
            shift 2
            ;;
        detect|configure|validate|generate|test|diagnose)
            COMMAND="$1"
            shift
            ;;
        *)
            error "Unknown option: $1"
            ;;
    esac
done

# Validate required parameters
if [[ -z "$COMMAND" ]]; then
    error "Command is required. Use --help for usage information."
fi

# Hypervisor detection functions
detect_hypervisor() {
    local detected=""
    
    # Check for QEMU/KVM
    if command -v virsh >/dev/null 2>&1; then
        if virsh list >/dev/null 2>&1; then
            detected="qemu"
        fi
    fi
    
    # Check for VMware
    if [[ -z "$detected" ]]; then
        if command -v vmrun >/dev/null 2>&1 || [[ -d "/proc/vmware" ]] || lsmod | grep -q vmware; then
            detected="vmware"
        fi
    fi
    
    # Check for VirtualBox
    if [[ -z "$detected" ]]; then
        if command -v VBoxManage >/dev/null 2>&1; then
            detected="vbox"
        fi
    fi
    
    # Check cloud environments
    if [[ -z "$detected" ]]; then
        if [[ -f "/sys/hypervisor/uuid" ]]; then
            local uuid=$(cat /sys/hypervisor/uuid 2>/dev/null || echo "")
            if [[ "$uuid" =~ ^ec2 ]]; then
                detected="aws"
            elif [[ "$uuid" =~ ^microsoft ]]; then
                detected="azure"
            fi
        fi
    fi
    
    # Fallback detection methods
    if [[ -z "$detected" ]]; then
        if dmesg | grep -qi "qemu\|kvm"; then
            detected="qemu"
        elif dmesg | grep -qi "vmware"; then
            detected="vmware"
        elif dmesg | grep -qi "vbox\|virtualbox"; then
            detected="vbox"
        fi
    fi
    
    echo "$detected"
}

# QEMU/KVM configuration functions
generate_qemu_xml() {
    local vm_name="$1"
    local socket_path="${2:-/var/lib/libvirt/qemu/channel/target}"
    
    cat << EOF
<!-- VirtIO Serial Configuration for InfiniService -->
<!-- Add to your domain XML within <devices> section -->

<!-- VirtIO Serial Controller -->
<controller type='virtio-serial' index='0'>
  <address type='pci' domain='0x0000' bus='0x00' slot='0x06' function='0x0'/>
</controller>

<!-- InfiniService Communication Channel -->
<channel type='unix'>
  <source mode='bind' path='${socket_path}/${vm_name}.org.infinibay.agent.0'/>
  <target type='virtio' name='org.infinibay.agent'/>
  <address type='virtio-serial' controller='0' bus='0' port='1'/>
</channel>

<!-- QEMU Guest Agent Channel -->
<channel type='unix'>
  <source mode='bind' path='${socket_path}/${vm_name}.org.qemu.guest_agent.0'/>
  <target type='virtio' name='org.qemu.guest_agent.0'/>
  <address type='virtio-serial' controller='0' bus='0' port='2'/>
</channel>
EOF
}

validate_libvirt_config() {
    local vm_name="$1"

    require_cmd virsh

    if ! virsh list --all | grep -q "$vm_name"; then
        if [[ "$FORCE" == "true" ]]; then
            warning "VM '$vm_name' not found in libvirt, but continuing due to --force"
        else
            error "VM '$vm_name' not found in libvirt."
        fi
    fi

    local xml_dump=$(virsh dumpxml "$vm_name")

    # Check for VirtIO serial controller
    if ! echo "$xml_dump" | grep -q "controller type='virtio-serial'"; then
        if [[ "$FORCE" == "true" ]]; then
            warning "VirtIO serial controller not found in VM configuration, but continuing due to --force"
        else
            warning "VirtIO serial controller not found in VM configuration."
            return 1
        fi
    fi

    # Check for InfiniService channel
    if ! echo "$xml_dump" | grep -q "name='org.infinibay.agent'"; then
        if [[ "$FORCE" == "true" ]]; then
            warning "InfiniService channel not found in VM configuration, but continuing due to --force"
        else
            warning "InfiniService channel not found in VM configuration."
            return 1
        fi
    fi

    success "QEMU/KVM configuration validation passed for VM '$vm_name'."
    return 0
}

apply_qemu_config() {
    local vm_name="$1"
    local socket_path="${2:-/var/lib/libvirt/qemu/channel/target}"

    require_cmd virsh

    if [[ "$DRY_RUN" == "true" ]]; then
        info "DRY RUN: Would apply QEMU configuration for VM '$vm_name'"
        generate_qemu_xml "$vm_name" "$socket_path"
        return 0
    fi

    # Create backup if requested
    if [[ "$BACKUP" == "true" ]]; then
        local backup_file="/tmp/${vm_name}-backup-$(date +%Y%m%d-%H%M%S).xml"
        virsh dumpxml "$vm_name" > "$backup_file"
        info "Backup created: $backup_file"
    fi

    # Check if VM is running
    local vm_running=false
    if virsh list | grep -q "$vm_name"; then
        vm_running=true
    fi

    # Generate device XML files
    local controller_xml="/tmp/${vm_name}-controller.xml"
    local channel_xml="/tmp/${vm_name}-channel.xml"

    # Generate VirtIO serial controller
    cat > "$controller_xml" << EOF
<controller type='virtio-serial' index='0'>
  <address type='pci' domain='0x0000' bus='0x00' slot='0x06' function='0x0'/>
</controller>
EOF

    # Generate InfiniService channel
    cat > "$channel_xml" << EOF
<channel type='unix'>
  <source mode='bind' path='${socket_path}/${vm_name}.org.infinibay.agent.0'/>
  <target type='virtio' name='org.infinibay.agent'/>
  <address type='virtio-serial' controller='0' bus='0' port='1'/>
</channel>
EOF

    # Apply configuration
    local attach_flags="--config"
    if [[ "$vm_running" == "true" ]]; then
        attach_flags="--config --live"
        info "VM is running, applying configuration to both persistent and live config"
    else
        info "VM is not running, applying configuration to persistent config only"
    fi

    # Attach controller first
    if virsh attach-device "$vm_name" "$controller_xml" $attach_flags 2>/dev/null; then
        success "VirtIO serial controller attached successfully"
    else
        warning "VirtIO serial controller may already exist or attachment failed"
    fi

    # Attach channel
    if virsh attach-device "$vm_name" "$channel_xml" $attach_flags 2>/dev/null; then
        success "InfiniService channel attached successfully"
    else
        warning "InfiniService channel may already exist or attachment failed"
    fi

    # Clean up temporary files
    rm -f "$controller_xml" "$channel_xml"

    info "QEMU configuration applied for VM '$vm_name'"
}

setup_socket_permissions() {
    local socket_path="${1:-/var/lib/libvirt/qemu/channel/target}"

    if [[ "$DRY_RUN" == "true" ]]; then
        info "DRY RUN: Would set up socket permissions at $socket_path"
        return 0
    fi

    # Create socket directory
    sudo mkdir -p "$socket_path"

    # Detect proper ownership from parent directory or existing files
    local parent_dir="$(dirname "$socket_path")"
    if [[ -d "$parent_dir" ]]; then
        sudo chown --reference="$parent_dir" "$socket_path"
        info "Set ownership based on parent directory: $parent_dir"
    else
        # Fallback: try to detect libvirt user
        local libvirt_user="qemu"
        local libvirt_group="qemu"

        # Check for common libvirt user variations
        if getent passwd libvirt-qemu >/dev/null 2>&1; then
            libvirt_user="libvirt-qemu"
            libvirt_group="kvm"
        elif getent passwd qemu >/dev/null 2>&1; then
            libvirt_user="qemu"
            libvirt_group="qemu"
        fi

        sudo chown "$libvirt_user:$libvirt_group" "$socket_path"
        info "Set ownership to detected libvirt user: $libvirt_user:$libvirt_group"
    fi

    sudo chmod 755 "$socket_path"

    # Set SELinux context if SELinux is enabled
    if command -v getenforce >/dev/null 2>&1 && [[ "$(getenforce)" != "Disabled" ]]; then
        sudo setsebool -P virt_use_comm on
        sudo restorecon -R "$socket_path"
        info "SELinux contexts configured for VirtIO sockets."
    fi

    success "Socket permissions configured at $socket_path"
}

# VMware configuration functions
generate_vmx_config() {
    local vm_name="$1"

    cat << 'EOF'
# Serial Port Configuration for InfiniService
# Add these lines to your VM's .vmx file

# InfiniService Communication Port
serial0.present = "TRUE"
serial0.fileType = "pipe"
serial0.fileName = "\\.\\pipe\\infinibay-agent"
serial0.pipe.endPoint = "server"
serial0.tryNoRxLoss = "FALSE"

# Additional serial port for guest tools
serial1.present = "TRUE"
serial1.fileType = "pipe"
serial1.fileName = "\\.\\pipe\\vmware-guest-agent"
serial1.pipe.endPoint = "server"
EOF
}

configure_vmware_pipes() {
    local vm_name="$1"

    if [[ "$DRY_RUN" == "true" ]]; then
        info "DRY RUN: Would configure VMware named pipes for VM '$vm_name'"
        return 0
    fi

    info "Named pipes will be created automatically by VMware when the VM starts."
    info "No manual pipe creation required."
}

validate_vmware_config() {
    local vm_name="$1"
    
    if ! command -v vmrun >/dev/null 2>&1; then
        warning "vmrun command not found. Cannot validate VMware configuration."
        return 1
    fi
    
    # This is a simplified validation - actual implementation would
    # need to parse .vmx files or use VMware APIs
    info "VMware configuration validation requires manual .vmx file inspection."
    info "Check for serial port configuration in VM settings."
    
    return 0
}

# VirtualBox configuration functions
configure_vbox_serial() {
    local vm_name="$1"

    require_cmd VBoxManage

    if [[ "$DRY_RUN" == "true" ]]; then
        info "DRY RUN: Would configure VirtualBox serial ports for VM '$vm_name'"
        return 0
    fi

    # Configure serial ports
    VBoxManage modifyvm "$vm_name" --uart1 0x3F8 4
    VBoxManage modifyvm "$vm_name" --uartmode1 server /tmp/infinibay-agent

    VBoxManage modifyvm "$vm_name" --uart2 0x2F8 3
    VBoxManage modifyvm "$vm_name" --uartmode2 server /tmp/vbox-guest-agent

    # Enable VirtIO support
    VBoxManage modifyvm "$vm_name" --paravirtprovider kvm

    success "VirtualBox serial ports configured for VM '$vm_name'"
}

setup_vbox_pipes() {
    local vm_name="$1"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        info "DRY RUN: Would set up VirtualBox host pipes"
        return 0
    fi
    
    # Create host pipes
    mkfifo /tmp/infinibay-agent 2>/dev/null || true
    chmod 666 /tmp/infinibay-agent
    
    mkfifo /tmp/vbox-guest-agent 2>/dev/null || true
    chmod 666 /tmp/vbox-guest-agent
    
    success "VirtualBox host pipes created"
}

validate_vbox_config() {
    local vm_name="$1"
    
    if ! command -v VBoxManage >/dev/null 2>&1; then
        error "VBoxManage command not found."
    fi
    
    local vm_info=$(VBoxManage showvminfo "$vm_name" 2>/dev/null || echo "")
    
    if [[ -z "$vm_info" ]]; then
        error "VM '$vm_name' not found in VirtualBox."
    fi
    
    # Check serial port configuration
    if echo "$vm_info" | grep -q "UART 1:.*0x03F8"; then
        success "VirtualBox serial port 1 configured correctly."
    else
        warning "VirtualBox serial port 1 not configured."
        return 1
    fi
    
    return 0
}

# Main command handlers
cmd_detect() {
    info "Detecting hypervisor environment..."
    
    local detected=$(detect_hypervisor)
    
    if [[ -n "$detected" ]]; then
        success "Detected hypervisor: $detected"
        
        case "$detected" in
            qemu)
                info "QEMU/KVM environment detected"
                info "Use: $SCRIPT_NAME configure --hypervisor qemu --vm-name <name>"
                ;;
            vmware)
                info "VMware environment detected"
                info "Use: $SCRIPT_NAME configure --hypervisor vmware --vm-name <name>"
                ;;
            vbox)
                info "VirtualBox environment detected"
                info "Use: $SCRIPT_NAME configure --hypervisor vbox --vm-name <name>"
                ;;
            aws|azure)
                info "Cloud environment detected: $detected"
                info "VirtIO configuration may be managed by cloud provider"
                ;;
        esac
    else
        warning "Could not detect hypervisor environment"
        info "Use --hypervisor option to specify manually"
    fi
}

cmd_configure() {
    if [[ -z "$VM_NAME" ]]; then
        error "VM name is required for configuration. Use --vm-name option."
    fi

    local hypervisor="${HYPERVISOR:-$(detect_hypervisor)}"

    if [[ -z "$hypervisor" ]]; then
        error "Could not detect hypervisor. Use --hypervisor option."
    fi

    info "Configuring for $hypervisor hypervisor, VM: $VM_NAME"

    case "$hypervisor" in
        qemu)
            setup_socket_permissions "$SOCKET_PATH"
            apply_qemu_config "$VM_NAME" "$SOCKET_PATH"
            success "QEMU/KVM configuration applied for VM '$VM_NAME'"
            ;;
        vmware)
            configure_vmware_pipes "$VM_NAME"
            info "VMware configuration:"
            generate_vmx_config "$VM_NAME"
            info "Manual .vmx file editing required. Configuration generated above."
            ;;
        vbox)
            setup_vbox_pipes "$VM_NAME"
            configure_vbox_serial "$VM_NAME"
            success "VirtualBox configuration completed for VM '$VM_NAME'"
            ;;
        *)
            error "Unsupported hypervisor: $hypervisor"
            ;;
    esac
}

cmd_validate() {
    if [[ -z "$VM_NAME" ]]; then
        error "VM name is required for validation. Use --vm-name option."
    fi
    
    local hypervisor="${HYPERVISOR:-$(detect_hypervisor)}"
    
    info "Validating VirtIO configuration for $hypervisor hypervisor, VM: $VM_NAME"
    
    case "$hypervisor" in
        qemu)
            validate_libvirt_config "$VM_NAME"
            ;;
        vmware)
            validate_vmware_config "$VM_NAME"
            ;;
        vbox)
            validate_vbox_config "$VM_NAME"
            ;;
        *)
            error "Unsupported hypervisor: $hypervisor"
            ;;
    esac
}

cmd_generate() {
    local hypervisor="${HYPERVISOR:-$(detect_hypervisor)}"
    
    if [[ -z "$hypervisor" ]]; then
        error "Could not detect hypervisor. Use --hypervisor option."
    fi
    
    info "Generating configuration for $hypervisor hypervisor"
    
    case "$hypervisor" in
        qemu)
            generate_qemu_xml "${VM_NAME:-infinibay-vm}" "$SOCKET_PATH"
            ;;
        vmware)
            generate_vmx_config "${VM_NAME:-infinibay-vm}"
            ;;
        vbox)
            info "VirtualBox configuration commands:"
            echo "VBoxManage modifyvm \"${VM_NAME:-infinibay-vm}\" --uart1 0x3F8 4"
            echo "VBoxManage modifyvm \"${VM_NAME:-infinibay-vm}\" --uartmode1 server /tmp/infinibay-agent"
            ;;
        *)
            error "Unsupported hypervisor: $hypervisor"
            ;;
    esac
}

cmd_test() {
    if [[ -z "$VM_NAME" ]]; then
        error "VM name is required for testing. Use --vm-name option."
    fi

    local hypervisor="${HYPERVISOR:-$(detect_hypervisor)}"

    info "Testing VirtIO connectivity for $hypervisor hypervisor, VM: $VM_NAME"

    case "$hypervisor" in
        qemu)
            local socket_path="${SOCKET_PATH:-/var/lib/libvirt/qemu/channel/target}"
            local socket_file="${socket_path}/${VM_NAME}.org.infinibay.agent.0"

            if [[ -S "$socket_file" ]]; then
                info "Testing socket communication: $socket_file"
                require_cmd socat
                echo "test" | timeout 5 socat - "UNIX-CONNECT:$socket_file" || warning "Socket test failed"
            else
                warning "Socket file not found: $socket_file"
            fi
            ;;
        vmware)
            info "VMware pipe testing requires VM to be running"
            info "Check named pipes: \\\\\.\\pipe\\infinibay-agent"
            ;;
        vbox)
            if [[ -p "/tmp/infinibay-agent" ]]; then
                info "Testing VirtualBox pipe communication"
                require_cmd timeout
                timeout 2 sh -c 'echo "test" > /tmp/infinibay-agent' || warning "Pipe test failed or timed out"
            else
                warning "VirtualBox pipe not found: /tmp/infinibay-agent"
            fi
            ;;
        *)
            error "Unsupported hypervisor: $hypervisor"
            ;;
    esac
}

cmd_diagnose() {
    info "Running comprehensive VirtIO diagnostics..."
    
    # Check if Windows diagnostic script exists
    local windows_diag="$SCRIPT_DIR/diagnose-virtio.ps1"
    if [[ -f "$windows_diag" ]]; then
        info "Windows diagnostic script available: $windows_diag"
        info "Run on Windows guest: powershell -ExecutionPolicy Bypass -File diagnose-virtio.ps1"
    fi
    
    # Run hypervisor-specific diagnostics
    local hypervisor="${HYPERVISOR:-$(detect_hypervisor)}"
    
    case "$hypervisor" in
        qemu)
            info "QEMU/KVM Diagnostics:"
            virsh list --all 2>/dev/null || warning "Cannot list VMs (virsh not available or no permissions)"
            ls -la /var/lib/libvirt/qemu/channel/target/ 2>/dev/null || warning "Cannot access socket directory"
            ;;
        vmware)
            info "VMware Diagnostics:"
            vmrun list 2>/dev/null || warning "Cannot list VMs (vmrun not available)"
            ;;
        vbox)
            info "VirtualBox Diagnostics:"
            VBoxManage list vms 2>/dev/null || warning "Cannot list VMs (VBoxManage not available)"
            ls -la /tmp/*infinibay* 2>/dev/null || warning "No VirtualBox pipes found"
            ;;
    esac
    
    # General system diagnostics
    info "System Information:"
    uname -a
    
    info "VirtIO Modules:"
    lsmod | grep virtio || warning "No VirtIO modules loaded"
    
    info "Serial Devices:"
    ls -la /dev/ttyS* /dev/vport* 2>/dev/null || warning "No serial devices found"
}

# Main execution
main() {
    info "Starting VM configuration script..."
    info "Log file: $LOG_FILE"

    case "$COMMAND" in
        detect)
            cmd_detect
            ;;
        configure)
            cmd_configure
            ;;
        validate)
            cmd_validate
            ;;
        generate)
            cmd_generate
            ;;
        test)
            cmd_test
            ;;
        diagnose)
            cmd_diagnose
            ;;
        *)
            error "Unknown command: $COMMAND"
            ;;
    esac

    info "Script execution completed."
}

# Run main function
main "$@"
