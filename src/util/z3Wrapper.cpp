#include <cstdint>
#include <string>
#include <z3++.h>
#include <vector>
#include <assert.h>
#include <cstddef>


class z3Wrapper {
    private:

        z3::context * ctx;

    public:

        z3Wrapper(z3::context * context) {
            z3Wrapper::ctx = context;
        }

    z3::expr bvs(std::string name, uint32_t size) {
        return ctx -> bv_const(name.c_str(), size);
    }

    z3::expr bvv(int32_t value, uint32_t size) {
        return ctx -> bv_val(value, size);
    }

    z3::expr_vector splitBVInList(const z3::expr expression) {
        return expression.args();
    }

    z3::expr bvvFromBytes(std::vector<std::byte> value) {
        assert(value.size() > 0);
        z3::expr* ret = nullptr;
        for (std::byte byte : value) {
            z3::expr e = ctx -> bv_val(std::to_integer<uint8_t>(byte), 8);
            if (ret == nullptr) {
                ret = &e;
            } else {
                *ret = z3::concat(*ret, e);
            }
        }
        return *ret;
    }

    std::tuple<z3::expr, z3::expr> splitBV(z3::expr expression, int32_t index) {
        assert(index > 0);
        assert(index < expression.length());
        return {
            expression.extract(expression.length() - 1, index).simplify(),
            expression.extract(index - 1, 0).simplify()
        };
    }

    bool symbolic(z3::expr expresssion) {
        return expresssion.simplify().decl().kind() != Z3_OP_BNUM;
    }

    int64_t bvv_to_long(z3::expr expression) {
        assert(!symbolic(expression)); // Check to see if expression is not symbolic.
        return expression.simplify().as_int64();
    }

    // TODO: Not super sure of the usefulness of this.
    uint64_t heuristicFindBase(z3::expr expression) {
        z3::expr_vector fringe = expression.args();
        while (fringe.size() > 0) {
            z3::expr element = fringe[fringe.size() - 1];
            fringe.resize(fringe.size() - 1);
            if (!symbolic(expression) && element.as_uint64() < 0x10000) {
                return element.as_uint64();
            } else {
                for (z3::expr arg : element.args())
                fringe.push_back(arg);
            }
        }
        return -1;
    }
};