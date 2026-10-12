# Bề mặt phát hiện của thao tác liên tiến trình trên Windows

Tài liệu này mô tả các tín hiệu phòng thủ có thể quan sát khi một tiến trình mở
hoặc thao tác với tiến trình khác. Mục đích là giúp kiểm thử và thiết kế giám sát
minh bạch; tài liệu không cung cấp hướng dẫn né tránh phát hiện.

### Handle

### Access mask

Một thao tác liên tiến trình thường bắt đầu bằng việc tạo **handle** tới tiến
trình đích. Kiểu đối tượng của handle (process, thread hoặc token), PID đích,
thời điểm tạo và nguồn tạo là các thuộc tính hữu ích cho việc đối chiếu. **Access
mask** cũng là tín hiệu quan trọng: `PROCESS_VM_READ`, `PROCESS_VM_WRITE`,
`PROCESS_VM_OPERATION`, `PROCESS_QUERY_INFORMATION` và quyền mở rộng như
`PROCESS_DUP_HANDLE` biểu thị mức khả năng mà bên gọi yêu cầu. Quyền cao bất
thường so với công việc của tiến trình, hoặc chuỗi mở/đóng handle dày đặc, có thể
được đưa vào quy tắc cảnh báo.

Handle có thể được quan sát ở lớp Win32 hoặc từ dữ liệu kernel. Việc kiểm tra
handle hợp lệ, quyền thực tế sau khi hệ thống chuẩn hóa yêu cầu, và quan hệ giữa
tiến trình gọi với tiến trình đích giúp giảm cảnh báo nhầm. Bản thân việc giữ một
handle hợp lệ đã tạo ra trạng thái có thể kiểm kê; đổi tên hàm gọi không xóa được
trạng thái đó.

### Call stack

**Call stack** cung cấp ngữ cảnh cho sự kiện mở handle, đọc/ghi bộ nhớ hoặc đổi
quyền bảo vệ trang. Stack có thể cho thấy mô-đun người dùng khởi phát, thư viện
trung gian, và điểm chuyển vào kernel. Khi phân tích, nên kết hợp stack với chữ
ký số, đường dẫn tệp, trạng thái tải mô-đun và danh tính tiến trình, thay vì chỉ
dựa vào một địa chỉ trả về. Stack không phải lúc nào cũng hoàn chỉnh, nhưng vẫn
là tín hiệu bổ sung tốt cho quyền, thời gian và tần suất.

### ETW

### Kernel callbacks

**ETW** (Event Tracing for Windows) cung cấp các phiên theo dõi cho tiến trình,
thread, image load, handle và nhiều hoạt động kernel khác. Bộ sưu tập ETW có thể
được ghép theo PID, TID, timestamp và địa chỉ đối tượng để dựng chuỗi sự kiện.
ETW không yêu cầu ứng dụng phải dùng đúng một API Win32 cụ thể; điều quan trọng là
hoạt động hệ thống phát sinh sự kiện quan sát được.

### ObRegisterCallbacks

Ở kernel, các thành phần phòng thủ có thể đăng ký **ObRegisterCallbacks** để nhận
thông báo trước/sau các thao tác trên process và thread object. Callback có thể
đánh giá caller, target, access mask và điều chỉnh quyền được cấp theo chính sách.
Đây là cơ chế kiểm soát và quan sát hợp lệ của nền tảng, không phải lời hứa rằng
một ứng dụng sẽ luôn bị chặn.

## Win32 so với native API

Win32 như `OpenProcess` và `ReadProcessMemory` đi qua các lớp thư viện chuẩn,
telemetry và kiểm tra quyền quen thuộc. Native API như `NtOpenProcess` hoặc
`NtReadVirtualMemory` ở lớp thấp hơn và có ABI khác, nhưng vẫn dẫn đến cùng các
đối tượng kernel và trạng thái quyền cần được bảo vệ. **Native syscalls vẫn có thể
quan sát được**: chúng tạo hoặc sử dụng handle, đi qua kernel, có thể xuất hiện
trong ETW và chịu các callback kernel phù hợp. Vì vậy việc gọi syscall trực tiếp
không biến hoạt động thành vô hình và không nên được xem là cơ chế né phát hiện.

### ETW-TI

**ETW-TI** (Threat Intelligence) bổ sung các tín hiệu phục vụ phát hiện hành vi
đáng ngờ ở lớp kernel và bảo mật nền tảng. Khi có dữ liệu ETW-TI, nên xem nó như
một phần của bằng chứng: kết hợp với access mask, call stack, signer, quan hệ
cha-con và chuỗi thời gian để đưa ra kết luận có thể giải thích.

### Handle stripping

**Handle stripping** là việc giảm hoặc loại bỏ các quyền nhạy cảm trên handle
trước khi cấp cho caller, thường theo chính sách của callback hoặc thành phần bảo
vệ. Việc này làm thay đổi khả năng thao tác nhưng vẫn để lại dấu vết của yêu cầu
và quyết định chính sách. Kiểm thử cần ghi nhận cả quyền yêu cầu lẫn quyền thực
tế nhận được.

### Process protection light

**Process protection light** (Protected Process Light, PPL) áp dụng cấp độ bảo
vệ dựa trên signer và loại bảo vệ. Một tiến trình thường không thể tùy ý mở hoặc
thao tác các quyền nhạy cảm trên tiến trình PPL có cấp cao hơn. Giám sát nên phân
biệt lỗi do chính sách bảo vệ với lỗi do PID, lifetime hoặc access mask không hợp
lệ; không nên coi việc thay đổi đường gọi là cách vượt qua PPL.

## Nguyên tắc sử dụng

Phân tích phòng thủ nên ghi lại API/lớp gọi, handle type, access mask, call stack,
ETW/ETW-TI, callback và kết quả quyền cuối cùng. Native syscall vẫn quan sát được
qua các hiệu ứng kernel và telemetry tương ứng. Tài liệu này chỉ hỗ trợ kiểm thử,
điều tra và hardening; không đưa ra hướng dẫn né tránh, che giấu hoặc vô hiệu hóa
các cơ chế phát hiện.
